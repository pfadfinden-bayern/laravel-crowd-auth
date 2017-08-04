<?php

/*
 * This file is part of CrowdAuth
 *
 * (c) Daniel McAssey <hello@glokon.me>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Crowd\Auth\Api;

use GuzzleHttp\Client as GuzzleClient;
use Http\Adapter\Guzzle6\Client as GuzzleAdapter;
use Http\Client\Common\Plugin\AuthenticationPlugin;
use Http\Client\Common\Plugin\ContentLengthPlugin;
use Http\Client\Common\Plugin\DecoderPlugin;
use Http\Client\Common\Plugin\HeaderSetPlugin;
use Http\Client\Common\Plugin\RedirectPlugin;
use Http\Client\Common\Plugin\RetryPlugin;
use Http\Client\Common\PluginClient;
use Http\Client\Exception\HttpException;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Message\Authentication\BasicAuth;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Class CrowdAPI
 *
 * @package Crowd\Auth\Api
 */
class CrowdAPI {
    
    /**
     * @var array
     */
    protected $_headers;
    
    /**
     * @var string
     */
    private $_endpointUrl;
    
    /**
     * @var GuzzleAdapter
     */
    private $_guzzleClient;
    
    /**
     * CrowdAPI constructor.
     *
     * @param $endpointUrl
     * @param $appName
     * @param $appPassword
     *
     * @throws RuntimeException
     */
    public function __construct($endpointUrl, $appName, $appPassword)
    {
        $guzzle       = new GuzzleClient();
        $guzzleClient = new GuzzleAdapter($guzzle);
        
        $authentication = new BasicAuth($appName, $appPassword);
    
        $defaultUserAgent = 'laravel-crowd-auth / v1.1.1 (https://gitlab.com/mglinski/laravel-crowd-auth) [Package Author: matthewglinski@gmail.com]';
    
        $this->_headers = [
            'Authorization'       => 'Basic '.base64_encode($appName . ':' . $appPassword),
            'Accept'       => 'application/json',
            'Content-Type' => 'application/json',
            'User-Agent'   => $defaultUserAgent,
        ];
    
        $headerDefaultsPlugin = new HeaderSetPlugin($this->_headers);
        
        // Instance Default Plugins
        $authenticationPlugin = new AuthenticationPlugin($authentication);
        $decoderPlugin        = new DecoderPlugin();
        $retryPlugin         = new RetryPlugin();
        $redirectPlugin      = new RedirectPlugin();
        $contentLengthPlugin = new ContentLengthPlugin();
        
        // Combine Plugins with Client
        $pluginClient = new PluginClient(
            $guzzleClient,
            [
                $authenticationPlugin,
                $headerDefaultsPlugin,
                $contentLengthPlugin,
                $retryPlugin,
                $redirectPlugin,
            ]
        );
    
        $this->_endpointUrl = $endpointUrl;
    
        // Save the HTTP Client instance
        $this->_guzzleClient = $pluginClient;
    
        // Setup the Request Instance Factory
        $this->requestFactory = MessageFactoryDiscovery::find();
    }
    
    /**
     * Authenticates user and gets SSO token
     *
     * @param  array  $credentials
     * @param  string $user_ip
     *
     * @return null|string
     * @throws \Exception
     */
    public function ssoAuthUser($credentials, $user_ip)
    {
        if (is_array($credentials) && isset($credentials['username']) && isset($credentials['password'])) {
            $apiEndpoint = '/1/session';
            $apiData     = [
                'username'           => $credentials['username'],
                'password'           => $credentials['password'],
                'validation-factors' => [
                    'validationFactors' => [
                        [
                            'name'  => 'remote_address',
                            'value' => $user_ip,
                        ],
                    ],
                ],
            ];
            $response    = $this->runCrowdAPI($apiEndpoint, 'POST', $apiData);
            
            if ($response->getStatusCode() == 201) {
                $data = json_decode((string)$response->getBody());
    
                logger()->debug('Crowd-Auth (' . __FUNCTION__ . ')', ['raw' => var_export($data, true)]);
                
                if ($credentials['username'] === $data->user->name) {
                    return $data->token;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Runs the data against the Crowd RESTful API
     *
     * @param  string $requestEndpoint
     * @param  string $requestType
     * @param  array  $requestData
     *
     * @return ResponseInterface
     * @throws \Exception
     */
    private function runCrowdAPI($requestEndpoint, $requestType, $requestData)
    {
        $resourcePath = $this->_endpointUrl . '/rest/usermanagement' . $requestEndpoint;
        if ($requestType === 'GET') {
            $resourcePath .= '?' . http_build_query($requestData);
            $requestData = '';
        } else if (is_array($requestData) || is_object($requestData)) {
            $requestData = json_encode($requestData);
        }

        /** @var RequestInterface $response */
        $request = $this->requestFactory->createRequest($requestType, $resourcePath, $this->_headers, $requestData);

        try {

            /** @var ResponseInterface $response */
            $response = $this->_guzzleClient->sendRequest($request);

            if ($response->getStatusCode() == 200 || $response->getStatusCode() == 201) {
//                logger()->debug('CrowdAuth Request Successful', [
//                    'request-method'  => $request->getMethod(),
//                    'request-uri'     => (string)$request->getUri(),
//                    'request-headers' => $request->getHeaders(),
//                    'request-body'    => (string)$request->getBody()->rewind(),
//
//                    'response-status'  => $response->getStatusCode(),
//                    'response-reason'  => $response->getReasonPhrase(),
//                    'response-headers' => $response->getHeaders(),
//                    'response-body'   => (string)$response->getBody()->rewind(),
//                ]);
            } else {
                logger()->debug('CrowdAuth Request FAILED', [
                    'request-method'  => $request->getMethod(),
                    'request-uri'     => (string)$request->getUri(),
                    'request-headers' => $request->getHeaders(),
                    'request-body'    => (string)$request->getBody()->rewind(),

                    'response-status'  => $response->getStatusCode(),
                    'response-reason'  => $response->getReasonPhrase(),
                    'response-headers' => $response->getHeaders(),
                    'response-body'   => (string)$response->getBody()->rewind(),
                ]);
            }

            return $response;
        } catch (HttpException $exception) {
            logger()->error('[CROWD AUTH] GUZZLE EXCEPTION - '.$exception->getMessage(), [
                'request-method'   => $exception->getRequest()->getMethod(),
                'request-uri'      => (string)$exception->getRequest()->getUri(),
                'request-headers'  => $exception->getRequest()->getHeaders(),
                'request-body'     => (string)$exception->getRequest()->getBody()->rewind(),

                'response-status' => $exception->getResponse()->getStatusCode(),
                'response-reason' => $exception->getResponse()->getReasonPhrase(),
                'response-headers' => $exception->getResponse()->getHeaders(),
                'response-body'    => (string)$exception->getResponse()->getBody()->rewind(),
            ]);
            throw $exception;
        }
    }
    
    /**
     * Retrieves user data from SSO token
     *
     * @param  string $username
     * @param  string $token
     *
     * @return array|null
     * @throws \Exception
     */
    public function ssoGetUser($username, $token)
    {
        $apiEndpoint = '/1/session/'.$token;
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', array());
        if ($response->getStatusCode() == 200) {
            $body = (string)$response->getBody()->getContents();
            $data = json_decode($body);

            logger()->error('CrowdAuth Request SSO USER DATA', [
                'data' => $data,
                'raw' => $body,
            ]);

            if ($data->user->name === $username && $token === $data->token) {
                return $this->getUser($data->user->name);
            }
        } else {
            logger()->error('CrowdAuth Request FAILURE', [
                'response-status' => $response->getStatusCode(),
                'response-reason' => $response->getReasonPhrase(),
                'response-headers' => $response->getHeaders(),
                'response-body'    => (string)$response->getBody()->rewind(),
            ]);
        }
        
        return null;
    }
    
    /**
     * Retrieves all user attributes and data.
     *
     * @param  string $username
     *
     * @return array|null
     * @throws \Exception
     */
    public function getUser($username)
    {
        $apiEndpoint = '/1/user';
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', [
            'username' => $username,
            'expand'   => 'attributes',
        ]);
        
        if ($response->getStatusCode() == 200) {
            $data = json_decode((string)$response->getBody());
    
            logger()->debug('Crowd-Auth (' . __FUNCTION__ . ')', ['raw' => var_export($data, true)]);

            $userData = [
                'key'          => $data->key,
                'user-name'    => $data->name,
                'first-name'   => $data->{'first-name'},
                'last-name'    => $data->{'last-name'},
                'display-name' => $data->{'display-name'},
                'email'        => $data->email,
                'attributes'   => [],
                'groups'       => $this->getUserGroups($data->name),
            ];
            
            return $userData;
        } else {
            logger()->debug('CrowdAuth Request FAILURE', [
                'request-method'  => $request->getMethod(),
                'request-uri'     => (string)$request->getUri(),
                'request-headers' => $request->getHeaders(),
                'request-body'    => (string)$request->getBody(),

                'response-status'  => $response->getStatusCode(),
                'response-reason'  => $response->getReasonPhrase(),
                'response-headers' => $response->getHeaders(),
                //'response-body'   => (string)$response->getBody(),
            ]);
        }
        
        return null;
    }
    
    /**
     * Gets all groups a user is a direct member of.
     *
     * @param  string $username
     *
     * @return array|null
     * @throws \Exception
     */
    public function getUserGroups($username)
    {
        $apiEndpoint = '/1/user/group/direct';
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', [
            'username' => $username,
        ]);
        
        if ($response->getStatusCode() == 200) {
            $data   = json_decode((string)$response->getBody());
    
            $groups = [];
            foreach ($data->groups as $group) {
                $groups[] = (string)$group->name;
            }
            
            return $groups;
        }
        
        return null;
    }
    
    /**
     * Retrieves the token if matched with sent token
     *
     * @param  string $token
     *
     * @return null|string
     * @throws \Exception
     */
    public function ssoGetToken($token)
    {
        $apiEndpoint = '/1/session/'.$token;
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', array());
        if ($response->getStatusCode() == 200) {
            $data = json_decode((string)$response->getBody());
            logger()->debug('Crowd-Auth (' . __FUNCTION__ . ')', ['raw' => var_export($data, true)]);
    
    
            return $data->token;
        }
        
        return null;
    }
    
    /**
     * Retrieves and updates the token if matched with sent token
     *
     * @param  string $token
     * @param         $user_ip
     *
     * @return null|string
     * @throws \Exception
     */
    public function ssoUpdateToken($token, $user_ip)
    {
        $apiEndpoint = '/1/session/'.$token;
        $apiData = (object)[
            'validationFactors' => [
                (object)[
                    'name'  => 'remote_address',
                    'value' => $user_ip,
                ]
            ],
        ];
        $response    = $this->runCrowdAPI($apiEndpoint, 'POST', $apiData);
        if ($response->getStatusCode() == 200) {
            $data = json_decode((string)$response->getBody());
            logger()->debug('Crowd-Auth (' . __FUNCTION__ . ')', ['raw' => var_export($data, true)]);
            
            return $data->token;
        }
        
        return null;
    }
    
    /**
     * Invalidates the token when logged out
     *
     * @param  string $token
     *
     * @return bool
     * @throws \Exception
     */
    public function ssoInvalidateToken($token)
    {
        $apiEndpoint = '/1/session/'.$token;
        $response    = $this->runCrowdAPI($apiEndpoint, 'DELETE', array());
        
        return $response->getStatusCode() == 204;
    }
    
    /**
     * Checks to see if user exists by username
     *
     * @param  string $username
     *
     * @return bool
     * @throws \Exception
     */
    public function doesUserExist($username)
    {
        $apiEndpoint = '/1/user';
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', [
            'username' => $username,
        ]);
        
        return $response->getStatusCode() == 200;
    }
    
    /**
     * Checks to see if the user can login to the application
     *
     * @param  string $username
     * @return bool
     */
    public function canUserLogin($username)
    {
//        $userGroups = $this->getUserGroups($username);
//        if (count($userGroups) > 0) {
//            if (count(array_intersect($userGroups, \Config::get('crowd-auth::app_groups'))) > 0) {
//                return true;
//            }
//        }
//        return false;
        
        return true;
    }
}
