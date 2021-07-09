<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Web Routes
|--------------------------------------------------------------------------
|
| Here is where you can register web routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| contains the "web" middleware group. Now create something great!
|
*/

Route::get('/', function () {
    return view('welcome');
});

// Admin Routes here==================================================
Route::group(['prefix'=>'admin', 'middleware'=>['admin:admin']], function(){
    Route::get('/login', [App\Http\Controllers\AdminController::class, 'showLogin']);
    Route::post('/login', [App\Http\Controllers\AdminController::class, 'adminLogin'])->name('admin.login');
    Route::get('/register', [App\Http\Controllers\AdminController::class, 'showRegister']);
    Route::post('/register', [App\Http\Controllers\AdminController::class, 'storeAdmin'])->name('admin.register');
});
Route::post('/admin/logout', [App\Http\Controllers\AdminController::class, 'Logout'])->name('admin.logout')->middleware('auth:admin');

Route::middleware(['auth.admin:admin', 'verified'])->get('admin/dashboard', function () {
    return view('admin.dashboard');
})->name('admin.dashboard');

Route::middleware(['auth:sanctum', 'verified'])->get('/dashboard', function () {
    return view('dashboard');
})->name('dashboard');
