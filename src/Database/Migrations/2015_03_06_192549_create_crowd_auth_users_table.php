<?php

/*
 * This file is part of CrowdAuth
 *
 * (c) Daniel McAssey <hello@glokon.me>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;

class CreateCrowdAuthUsersTable extends Migration
{

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('crowd_auth_users', function (Blueprint $table)
        {
            $table->increments('id');
            $table->string('crowd_key')->unique();
            $table->string('token')->unique();
            $table->string('username')->default('');
            $table->string('email')->default('');
            $table->string('display_name')->default('');
            $table->string('first_name')->default('');
            $table->string('last_name')->default('');
            $table->rememberToken();
            $table->timestamps();
        });
    }
    
    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('crowd_auth_users');
    }
}
