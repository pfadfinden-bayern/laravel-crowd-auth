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
use Http\Client\Common\Plugin\HeaderDefaultsPlugin;
use Http\Client\Common\Plugin\RedirectPlugin;
use Http\Client\Common\Plugin\RetryPlugin;
use Http\Client\Common\PluginClient;
use Http\Discovery\MessageFactoryDiscovery;
use Http\Message\Authentication\BasicAuth;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * Class CrowdAPI
 *
 * @package Crowd\Auth\Api
 */
class CrowdAPI {
    
    
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
        
        $defaultUserAgent     = 'laravelcrowd-auth / v1.0 [matthewglinski@gmail.com]';
        $headerDefaultsPlugin = new HeaderDefaultsPlugin([
            'Accept: application/json',
            'Content-Type: application/json',
            'User-Agent' => $defaultUserAgent,
        ]);
        
        // Instance Default Plugins
        $authenticationPlugin = new AuthenticationPlugin($authentication);
        $decoderPlugin        = new DecoderPlugin();
        $retryPlugin          = new RetryPlugin();
        $redirectPlugin       = new RedirectPlugin();
        $contentLengthPlugin  = new ContentLengthPlugin();
        
        // Combine Plugins with Client
        $pluginClient = new PluginClient(
            $guzzleClient,
            [
                $authenticationPlugin,
                $headerDefaultsPlugin,
                $contentLengthPlugin,
                $retryPlugin,
                $redirectPlugin,
                $decoderPlugin,
            ]
        );
        
        // Save the HTTP Client instance
        $this->guzzleClient = $pluginClient;
        
        // Setup the Request Instance Factory
        $this->requestFactory = MessageFactoryDiscovery::find();
        
        $this->_endpointUrl  = $endpointUrl;
        $this->_guzzleClient = $guzzleClient;
    }
    
    /**
     * Authenticates user and gets SSO token
     *
     * @param  array  $credentials
     * @param  string $user_ip
     *
     * @return null|string
     */
    public function ssoAuthUser($credentials, $user_ip)
    {
        if (is_array($credentials) && isset($credentials['username']) && isset($credentials['password'])) {
            $apiEndpoint = '/1/session';
            $apiData = [
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
            $response = $this->runCrowdAPI($apiEndpoint, 'POST', $apiData);
            
            if ($response->getStatusCode() === 201) {
                $data = $response->json();
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
    private function runCrowdAPI($requestEndpoint, $requestType, array $requestData)
    {
        $resourcePath = $this->_endpointUrl . '/rest/usermanagement' . $requestEndpoint;
        if ($requestType === 'GET') {
            $resourcePath .= '?' . http_build_query($requestData);
            $requestData = [];
        }
    
        $request = $this->requestFactory->createRequest($requestType, $resourcePath, [], $requestData);
    
        $promise = $this->_guzzleClient->sendAsyncRequest($request);
        
        /** @var ResponseInterface $response */
        $response = $promise->wait();
        
        return $response;
    }
    
    /**
     * Retrieves user data from SSO token
     *
     * @param  string $username
     * @param  string $token
     * @return array|null
     */
    public function ssoGetUser($username, $token)
    {
        $apiEndpoint = '/1/session/'.$token;
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', array());
        if ($response->getStatusCode() === 200) {
            $data = $response->json();
            if ($data->user->name === $username && $token === $data->token) {
                return $this->getUser($data->user->name);
            }
        }
        
        return null;
    }
    
    /**
     * Retrieves all user attributes and data.
     *
     * @param  string $username
     *
     * @return array|null
     */
    public function getUser($username)
    {
        $apiEndpoint = '/1/user';
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', [
            'username' => $username,
            'expand'   => 'attributes',
        ]);
        
        if ($response->getStatusCode() === 200) {
            $data           = $response->json();
            $userAttributes = [];
            
            $count = count($data->attributes->attributes);
            
            for ($i = 0; $i < $count; $i++) {
                $currentAttribute                          = $data->attributes->attributes[$i];
                $userAttributes[$currentAttribute['name']] = $currentAttribute['values'][0];
            }
            
            $userData = [
                'key'          => $response->key,
                'user-name'    => $response->name,
                'first-name'   => $response->{'first-name'},
                'last-name'    => $response->{'last-name'},
                'display-name' => $response->{'display-name'},
                'email'        => $response->email,
                'attributes'   => $userAttributes,
                'groups'       => $this->getUserGroups($response->name),
            ];
            
            return $userData;
        }
        
        return null;
    }
    
    /**
     * Gets all groups a user is a direct member of.
     *
     * @param  string $username
     *
     * @return array|null
     */
    public function getUserGroups($username)
    {
        $apiEndpoint = '/1/user/group/direct';
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', [
            'username' => $username,
        ]);
        
        if ($response->getStatusCode() === 200) {
            $data   = $response->json();
            $groups = [];
            $count  = count($data->groups);
            for ($i = 0; $i < $count; $i++) {
                $groups[] = $data->groups[$i]['name'];
            }
            
            return $groups;
        }
        
        return null;
    }
    
    /**
     * Retrieves the token if matched with sent token
     *
     * @param  string $token
     * @return string|null
     */
    public function ssoGetToken($token)
    {
        $apiEndpoint = '/1/session/'.$token;
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', array());
        if ($response->getStatusCode() === 200) {
            $data = $response->json();
            
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
     */
    public function ssoUpdateToken($token, $user_ip)
    {
        $apiEndpoint = '/1/session/'.$token;
        $apiData     = [
            'validationFactors' => [
                'name'  => 'remote_address',
                'value' => $user_ip,
            ],
        ];
        $response    = $this->runCrowdAPI($apiEndpoint, 'POST', $apiData);
        if ($response->getStatusCode() === 200) {
            $data = $response->json();
            
            return $data->token;
        }
        
        return null;
    }
    
    /**
     * Invalidates the token when logged out
     *
     * @param  string $token
     * @return bool
     */
    public function ssoInvalidateToken($token)
    {
        $apiEndpoint = '/1/session/'.$token;
        $response    = $this->runCrowdAPI($apiEndpoint, 'DELETE', array());
        
        return $response->getStatusCode() === 204;
    }
    
    /**
     * Checks to see if user exists by username
     *
     * @param  string $username
     * @return bool
     */
    public function doesUserExist($username)
    {
        $apiEndpoint = '/1/user';
        $response    = $this->runCrowdAPI($apiEndpoint, 'GET', [
            'username' => $username,
        ]);
        
        return $response->getStatusCode() === 200;
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
