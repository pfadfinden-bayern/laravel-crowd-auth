<?php namespace Crowd\Auth\Providers;

use Crowd\Auth\Models\CrowdGroup;
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
            if (resolve('crowd-api')->doesUserExist($identifier)) {
                
                $userData = resolve('crowd-api')->getUser($identifier);
                if (!empty($userData)) {
                    return new GenericUser([
                        'id'           => $userData['user-name'],
                        'username'     => $userData['user-name'],
                        'key'          => $userData['key'],
                        'display_name' => $userData['display-name'],
                        'first_name'   => $userData['first-name'],
                        'last_name'    => $userData['last-name'],
                        'email'        => $userData['email'],
                        'user_groups'  => $userData['groups'],
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
        if (resolve('crowd-api')->canUserLogin($credentials['username'])) {
    
            try {
                // Attempt the sso checks
                $ip_address = filter_var($_SERVER['REMOTE_ADDR'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        
                $token = resolve('crowd-api')->ssoAuthUser($credentials, $ip_address);
                if ($token === null) {
                    return false;
                }
        
                $sso_user = resolve('crowd-api')->ssoGetUser($credentials['username'], $token);
                if ($sso_user === null) {
                    return false;
                }
        
            } catch (\Exception $exception) {
                return false;
            }
    
            // Check if user exists in DB, if not add it.
            $stored_crowd_user = CrowdUser::where('crowd_key', '=', $user->key)->first();
            if ($stored_crowd_user === null) {
                $stored_crowd_user = CrowdUser::create([
                    'crowd_key'    => $user->key,
                    'username'     => $user->username,
                    'email'        => $user->email,
                    'token'        => $token,
                    'display_name' => $user->display_name,
                    'first_name'   => $user->first_name,
                    'last_name'    => $user->last_name,
                ]);
            }
    
            // Detach all old groups from user and re-attach current ones.
            $stored_crowd_user->groups()->detach();
    
            // Save new groups breh
            foreach ($user->user_groups as $group_name) {
    
                // Check if user_group already exists in the DB, if not add it.
                $crowdUserGroup = CrowdGroup::firstOrNew([
                    'name' => $group_name,
                ]);
                
                // Check if user has a group retrieved from Crowd
                if (!$stored_crowd_user->isMemberOf($crowdUserGroup->name)) {
                    $stored_crowd_user->groups()->attach($crowdUserGroup);
                }
            }
    
            $stored_crowd_user->save();
            return true;
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
        $userData = CrowdUser::where('name', '=', $identifier)->where('remember_token', '=', $token)->first();
        if ($userData !== null) {
            return $this->retrieveById($userData['username']);
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
            $user->setRememberToken($token);
        }
        
        return null;
    }
}
