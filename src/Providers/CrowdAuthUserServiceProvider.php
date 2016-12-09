<?php namespace Crowd\Auth\Providers;

use Crowd\Auth\Models\CrowdUser;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\UserInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

/**
 * Class CoreAuthUserServiceProvider
 *
 * @package Brave\Core\Providers
 */
class CrowdAuthUserServiceProvider implements UserProvider
{
    
    /**
     * @var CoreAuthUser
     */
    protected $auth_user_model;
    
    /**
     * @var CoreAuthPermission
     */
    protected $auth_permission_model;
    
    /**
     * @var CoreAuthGroup
     */
    protected $auth_group_model;
    
    /**
     * @var Config
     */
    protected $config;
    
    /**
     * @var CoreAuthGroup
     */
    protected $debug;
    
    /**
     * @param ConfigRepository $config
     */
    public function __construct(ConfigRepository $config)
    {
        $this->config = $config;
        $this->debug  = $this->config->get('app.debug');
    }
    
    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     *
     * @return GenericUser|null
     */
    public function retrieveByCredentials(array $credentials)
    {
        if (isset($credentials['username'])) {
            return $this->retrieveById($credentials['username']);
        }
        
        return null;
    }
    
    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed $identifier
     *
     * @return GenericUser|null
     */
    public function retrieveById($identifier)
    {
        if ($identifier !== null) {
            if (resolve('crowd-auth')->doesUserExist($identifier)) {
                $userData = resolve('crowd-auth')->getUser($identifier);
                if (!empty($userData)) {
                    return new GenericUser([
                        'id'          => $userData['user-name'],
                        'username'    => $userData['user-name'],
                        'key'         => $userData['key'],
                        'displayName' => $userData['display-name'],
                        'firstName'   => $userData['first-name'],
                        'lastName'    => $userData['last-name'],
                        'email'       => $userData['email'],
                        'usergroups'  => $userData['groups'],
                    ]);
                }
            }
        }
        
        return null;
    }
    
    /**
     * Validate a user against the given credentials.
     *
     * @param  Authenticatable $user
     * @param  array           $credentials
     *
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        if (resolve('crowd-auth')->canUserLogin($credentials['username'])) {
            $token = resolve('crowd-auth')->ssoAuthUser($credentials,
                filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4));
            if ($token !== null && resolve('crowd-auth')->ssoGetUser($credentials['username'], $token) !== null) {
                
                // Check if user exists in DB, if not add it.
                $stored_crowd_user = CrowdUser::where('crowd_key', '=', $user->key)->first();
                if ($stored_crowd_user === null) {
                    $stored_crowd_user = CrowdUser::create(array(
                        'crowd_key'    => $user->key,
                        'username'     => $user->username,
                        'email'        => $user->email,
                        'display_name' => $user->displayName,
                        'first_name'   => $user->firstName,
                        'last_name'    => $user->lastName,
                    ));
                }
                
                // Detach all old groups from user and re-attach current ones.
                $stored_crowd_user->groups()->detach();
                
                // Save new groups breh
                foreach ($user->usergroups as $usergroup) {
                    +
                        
                        // Check if usergroup already exists in the DB, if not add it.
                    $crowdUserGroup = CrowdGroup::where('group_name', '=', $usergroup)->first();
                    if ($crowdUserGroup === null) {
                        $crowdUserGroup = CrowdGroup::create(array(
                            'group_name' => $usergroup,
                        ));
                    }
                    
                    // Check if user has a group retrieved from Crowd
                    if ($stored_crowd_user->isMemberOf($crowdUserGroup->id) === false) {
                        $stored_crowd_user->groups()->attach($crowdUserGroup);
                    }
                }
                
                $stored_crowd_user->save();
                $user->setRememberToken($token);
                
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Retrieve a user by by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string $token
     *
     * @return GenericUser|null
     */
    public function retrieveByToken($identifier, $token)
    {
        $userData = resolve('crowd-auth')->ssoGetUser($identifier, $token);
        if ($userData !== null) {
            return $this->retrieveById($userData['user-name']);
        }
        
        return null;
    }
    
    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  Authenticatable $user
     * @param  string          $token
     *
     * @return null
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        if ($user !== null) {
            $user->setRememberToken(resolve('crowd-auth')->ssoUpdateToken($token,
                filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)));
        }
        
        return null;
    }
}
