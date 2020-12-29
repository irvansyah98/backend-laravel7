<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

// Route::middleware('auth:api')->get('/user', function (Request $request) {
//     return $request->user();
// });

Route::post("register", "UserController@register");

Route::post("login", "UserController@login");

Route::get('/users', 'UserController@index')->middleware('jwt.verify');
Route::post('/user/store', 'UserController@store')->middleware('jwt.verify');
Route::get('/user/edit/{id}', 'UserController@getUser')->middleware('jwt.verify');
Route::get('/user/{id}', 'UserController@getUser')->middleware('jwt.verify');
Route::put('/user/{id}', 'UserController@update')->middleware('jwt.verify');
Route::delete('/user/delete/{id}', 'UserController@delete')->middleware('jwt.verify');