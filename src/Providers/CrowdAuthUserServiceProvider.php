<?php namespace Crowd\Auth\Providers;

use Carbon\Carbon;
use Crowd\Auth\Api\CrowdAPI;
use Crowd\Auth\Models\CrowdGroup;
use Crowd\Auth\Models\CrowdUser;
use Exception;
use Illuminate\Auth\UserInterface;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Database\Eloquent\Model;

/**
 * Class CoreAuthUserServiceProvider
 *
 * @package Crowd\Auth\Providers
 */
class CrowdAuthUserServiceProvider implements UserProvider
{
    
    /**
     * Laravel App Config object
     *
     * @var Config
     */
    protected $config;
    
    /**
     * Laravel App Custom User Model
     *
     * @var Model
     */
    protected $userModel;
    
    /**
     * Laravel App Config object
     *
     * @var CrowdAPI
     */
    protected $crowdApi;
    
    /**
     * @param ConfigRepository $config
     */
    public function __construct(ConfigRepository $config)
    {
        $this->config = $config;
        $this->userModel = $config['crowd_auth.user_model'];
        $this->crowdApi = resolve('crowd.api');
    }
    
    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array $credentials
     *
     * @return CrowdUser|null
     * @throws Exception
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
     * @param string|int $identifier The username of the SSO user
     *
     * @return CrowdUser
     * @throws Exception
     */
    public function retrieveById($identifier)
    {
        // if we get no identifier.... I just dont know.
        if (!empty($identifier)) {
            
            // We will only ever get an integer identifier if the user was previously authed
            if (is_int($identifier)) {
                
                // Find the authed user
                $user       = $this->userModel::find($identifier);
    
                // if user is not found
                if (!$user) {
                    return null;
                }
                $identifier = $user->username;
                
                // Only force an SSO update/recheck of the user every 5 minutes
                $checkTime = Carbon::now()->subSeconds($this->config['crowd_auth.refresh_interval']);
                if (!$user->updated_at < $checkTime) {
                    return $user;
                }
            }
            
            // We need to check with the SSO endpoint to see if this user still exists
            if ($this->crowdApi->doesUserExist($identifier)) {
                
                // Ok user exists, now we can get the details of the user.
                $userData = $this->crowdApi->getUser($identifier);
                
                // Now that we have the user, we can attempt to validate the data locally.
                if (!empty($userData)) {
                    
                    // Check if user exists in DB, if not create an in-memory model and pass it along.
                    return $this->userModel::firstOrNew([
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
        if ($this->crowdApi->canUserLogin($credentials['username'])) {
            
            try {
                // Attempt the sso checks
                $token = $this->crowdApi->ssoAuthUser($credentials, request()->ip());
                if (empty($token)) {
                    
                    // No token? No Access.
                    return false;
                }
    
                $sso_user = $this->crowdApi->ssoGetUser($credentials['username'], $token);
                if (empty($sso_user)) {
                    return false;
                }
    
                // Does the expected user data match?
                if ($sso_user['key'] !== $storedCrowdUser->crowd_key || $sso_user['user-name'] !== $storedCrowdUser->username) {
                    return false;
                }
    
            } catch (Exception $exception) {
                return false;
            }
    
            // While this method is just meant to validate that some credentials match a valid user object,
            // we have to do some work here to make sure we are getting valid user data in our database.
            // This works in concert with `$this->retrieveById()` to fully update the user object with any new user data.
            $storedCrowdUser->display_name = $sso_user['display-name'];
            $storedCrowdUser->first_name   = $sso_user['first-name'];
            $storedCrowdUser->last_name    = $sso_user['last-name'];
    
            // Update the stored SSO token.
            $storedCrowdUser->sso_token = $token;
            
            // Save group associations and any newly created groups to the DB
            $groups = [];
            foreach ($sso_user['groups'] as $group_name) {
                
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
            }
            
            // Finally save all the user data to the DB
            $storedCrowdUser->save();
    
            // Update accessible groups on the user
            $storedCrowdUser->groups()->sync($groups);
            
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
     * @return CrowdUser|Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        return $this->userModel::where('id', '=', $identifier)->where('remember_token', '=', $token)->first();
    }
    
    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param  CrowdUser|Authenticatable|null $user
     * @param  string                         $token
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
