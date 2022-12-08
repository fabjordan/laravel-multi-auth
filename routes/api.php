<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

use App\Http\Controllers\API\AuthController;
use App\Http\Controllers\API\AuthJwtController;
use App\Http\Controllers\API\BlogController;

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

Route::post('login-jwt', [AuthJwtController::class, 'login'])->withoutMiddleware(['api']);

Route::post('login', [AuthController::class, 'signin'])->withoutMiddleware(['api', 'auth:sanctum']);
Route::post('register', [AuthController::class, 'signup'])->withoutMiddleware(['api']);

Route::middleware(['auth:sanctum'])->group(function () {
    Route::resource('blogs', BlogController::class);
});

Route::get('teste', function () {
    return response()->json(['message' => 'teste']);
})->middleware(['auth:sanctum']);

Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
    return $request->user();
});
