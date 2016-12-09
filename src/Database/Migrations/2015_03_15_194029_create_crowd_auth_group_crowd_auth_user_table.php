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

class CreateCrowdAuthGroupCrowdAuthUserTable extends Migration
{

    /**
     * Run the migrations.
     *
     * @return void
     */
    public function up()
    {
        Schema::create('crowd_auth_group_auth_user', function (Blueprint $table)
        {
            $table->increments('id');
            $table->integer('crowd_group_id')->unsigned()->index();
            $table->integer('crowd_user_id')->unsigned()->index();
            $table->timestamps();
        });
    
        Schema::table('crowd_auth_group_auth_user', function (Blueprint $table)
        {
            $table->foreign('crowd_group_id')->references('id')->on('crowd_auth_groups')->onDelete('cascade');
            $table->foreign('crowd_user_id')->references('id')->on('crowd_auth_users')->onDelete('cascade');
        });
    }


    /**
     * Reverse the migrations.
     *
     * @return void
     */
    public function down()
    {
        Schema::drop('crowd_auth_group_auth_user');
    }

}
