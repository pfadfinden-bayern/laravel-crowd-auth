<?php namespace Crowd\Auth\Providers;

use Crowd\Auth\Models\CrowdGroup;
use Crowd\Auth\Models\CrowdUser;
use Illuminate\Auth\UserInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Request;

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
     * @param ConfigRepository $config
     */
    public function __construct(ConfigRepository $config)
    {
        $this->config = $config;
    }
    
    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     *
     * @return CrowdUser|null
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
     * @param string $identifier The username of the SSO user
     *
     * @return CrowdUser
     */
    public function retrieveById($identifier)
    {
        if ($identifier !== null) {
    
            // We need to check with the SSO endpoint to see if this user still exists
            if (resolve('crowd-api')->doesUserExist($identifier)) {
    
                // Ok user exists, now we can get the details of the user.
                $userData = resolve('crowd-api')->getUser($identifier);
    
                // Now that we have the user, we can attempt to validate the data locally.
                if (!empty($userData)) {
    
                    // Check if user exists in DB, if not create an in-memory model and pass it along.
                    return CrowdUser::firstOrNew([
                        'crowd_key' => $userData['key'],
                        'username'  => $userData['user-name'],
                        'email'     => $userData['email'],
                    ]);
                }
            }
        }
        
        return null;
    }
    
    /**
     * Validate a user against the given credentials.
     *
     * @param  Authenticatable|CrowdUser $storedCrowdUser
     * @param  array                     $credentials
     *
     * @return bool
     */
    public function validateCredentials(Authenticatable $storedCrowdUser, array $credentials)
    {
        if (resolve('crowd-api')->canUserLogin($credentials['username'])) {
    
            try {
                // Attempt the sso checks
                $token = resolve('crowd-api')->ssoAuthUser($credentials, request()->ip());
                if ($token === null) {
                    // No token? No Access.
                    return false;
                }
        
                $sso_user = resolve('crowd-api')->ssoGetUser($credentials['username'], $token);
                if ($sso_user === null) {
                    return false;
                }
        
                // Does the expected user match?
                if ($sso_user->key !== $storedCrowdUser->crowd_key || $sso_user->username !== $storedCrowdUser->username) {
                    return false;
                }
                
            } catch (\Exception $exception) {
                return false;
            }
    
            // While this method is just ment to validate that some credentials match a valud u ser object,
            // we have to do some work here to make sure we are getting valid user data in our database.
            // This works in concert with `$this->retrieveById()` to fully update the user object with any new user data.
            $storedCrowdUser->display_name = $sso_user->display_name;
            $storedCrowdUser->first_name   = $sso_user->first_name;
            $storedCrowdUser->last_name    = $sso_user->last_name;
    
            // Update the SSO token.
            $storedCrowdUser->sso_token = $token;
            
            // Detach all old groups from user and re-attach current ones.
            $storedCrowdUser->groups()->detach();
    
            // Save group associations and any newly created groups to the DB
            $groups = [];
            foreach ($sso_user->groups as $group_name) {
                
                // Check if user_group already exists in the DB, if not add it.
                $crowdUserGroup = CrowdGroup::firstOrNew([
                    'name' => $group_name,
                ]);
        
                // save to the DB if it does not exist
                if (!$crowdUserGroup->exists) {
                    $crowdUserGroup->save();
                }
    
                // get the group ID and attach it to the sync object
                $groups[] = $crowdUserGroup->id;
    
                // Update groups on the user
                $storedCrowdUser->groups()->sync($groups);
            }
    
            // Finally save all the user data to the DB
            $storedCrowdUser->save();
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
     * @return CrowdUser|null
     */
    public function retrieveByToken($identifier, $token)
    {
        $userData = CrowdUser::where('id', '=', $identifier)->where('remember_token', '=', $token)->first();
    
        return $userData;
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
            $user->save();
        }
        return null;
    }
}
