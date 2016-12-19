<?php

/*
 * This file is part of CrowdAuth
 *
 * (c) Daniel McAssey <hello@glokon.me>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Crowd\Auth\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class CrowdUser extends Authenticatable
{
    /**
     * Whitelist
     *
     * Allow for mass Assignment
     *
     * @var array
     */
    protected $fillable = [
        'crowd_key',
        'username',
        'email',
        'display_name',
        'first_name',
        'last_name',
        'sso_token',
        'remember_token',
    ];
    
    /**
     * The attributes that should be hidden for arrays.
     *
     * @var array
     */
    protected $hidden = [
        'sso_token',
        'remember_token',
    ];
    
    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'crowd_auth_users';
    
    /**
     * Get the unique identifier for the user.
     *
     * @return mixed
     */
    public function getAuthIdentifier()
    {
        return $this->getKey();
    }
    
    /**
     * Get the password for the user.
     *
     * @return string
     */
    public function getAuthPassword()
    {
        return $this->password;
    }
    
    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     */
    public function getRememberToken()
    {
        return $this->remember_token;
    }
    
    /**
     * Set the token value for the "remember me" session.
     *
     * @param  string $value
     *
     * @return void
     */
    public function setRememberToken($value)
    {
        $this->remember_token = $value;
    }
    
    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     */
    public function getRememberTokenName()
    {
        return 'remember_token';
    }
    
    /**
     * Checks if a user is member of a group
     *
     * @param string $group
     *
     * @return bool
     */
    public function isMemberOf($group)
    {
        return $this->groups->contains('name', $group);
    }
    
    /**
     * Get User ID by User name
     *
     * @param        $query
     * @param string $name
     *
     * @return mixed
     */
    public function scopeIdByName($query, $name)
    {
        return $query->select('id')->where('display_name', 'LIKE', "%{$name}%");
    }
    
    /**
     * Get all groups that belong to the user
     *
     * @return CrowdGroup
     */
    public function groups()
    {
        return $this->belongsToMany('\Crowd\Auth\Models\CrowdGroup', 'crowd_auth_group_auth_user', 'crowd_user_id',
            'crowd_group_id')->withTimestamps();
    }
}
