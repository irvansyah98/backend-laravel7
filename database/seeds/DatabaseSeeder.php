<?php

use Illuminate\Database\Seeder;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        // $this->call(UserSeeder::class);
        $result = DB::table('users')->insert([
            'firstname' => 'admin',
            'lastname' => '123',
            'email' => 'admin@gmail.com',
            'password' => \Hash::make('sandiaman'),
            'phone' => '12345',
            'city' => '12345',
            'country' => '12345',
            'birthdate'=>'2020-02-02',
            'isAdmin' => 1,
            'created_at' => new DateTime,
            'updated_at' => new DateTime,
        ]);
    }
}
