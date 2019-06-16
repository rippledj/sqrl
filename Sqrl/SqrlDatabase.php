<?php
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2019 Joseph Lee
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace Sqrl;
use \PDO;

/**
 * Class for a SQRL database connection object
 */
class SqrlDatabase
{

    /**
     * @var object $db_connection The database connection for each db
     */
    public $db_connection = null; // connection for application system data

    /**
     * @var object $db_status The database connection status for each db
     */
    public $db_status = null; // status of application system data connection


    public function __construct()
    {
      if($this->db_connection instanceof PDO){
          $this->db_status = true;
      }else{

        //load database config constants
        require_once SQRL_PHP_DIRPATH.'config/db_config.php';

        try{
            $this->db_connection = new PDO(DB_APPLICATION.':host='. DB_HOST .';dbname='. DB_NAME . ';charset=utf8', DB_USERNAME, DB_PASSWORD);
            $this->db_status = true;
            $this->db_connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            // Return the database connection to the main application
            return $this->db_connection;

        }catch (PDOException $e){
            trigger_error("Database Connection Error: ".$e->getMessage(), E_USER_ERROR);
            $this->user_db_status = false;
            return false;
        }

      }
    }

}
