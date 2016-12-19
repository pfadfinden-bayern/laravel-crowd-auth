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

use Illuminate\Database\Eloquent\Model;

/**
 * Class CrowdGroup
 *
 * @property-write int name The name of the group
 *
 * @package Crowd\Auth\Models
 */
class CrowdGroup extends Model
{
    /**
     * Whitelist
     *
     * Allow for mass Assignment
     *
     * @var array
     */
    protected $fillable = ['name'];

    /**
     * The database table used by the model.
     *
     * @var string
     */
    protected $table = 'crowd_auth_groups';

    /**
     * Get all users that use this group
     *
     * @return CrowdUser
     */
    public function users() {
        return $this->belongsToMany('Crowd\Auth\Models\CrowdUser', 'crowd_auth_group_auth_user', 'crowd_group_id',
            'crowd_user_id')->withTimestamps();
    }
}
