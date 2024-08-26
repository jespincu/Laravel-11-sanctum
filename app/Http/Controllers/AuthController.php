<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request){
        // Validate request data
        $request->validate([
            'name' => ['required','string','max:255'],
            'email' => ['required','string','email','max:255','unique:users'],
            'password' => ['required','string','min:8','confirmed'],
        ]);

        // Create a new user
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        // Generate a JWT token for the user
        $token = $user->createToken($request->email)->plainTextToken;

        return [
           'user' => $user,
           'token' => $token
        ];
    }

    public function login( Request $request){
        // Validate request data
        $request->validate([
            'email' => 'required|email|string|exists:users',
            'password' => 'required|max:8',
        ]);

        $user = User::where('email', $request->email)->first();

        if(!$user || !Hash::check($request->password, $user->password)){
            return [
                'message' => 'Invalid credentials'
            ];
        }

        // Generate a JWT token for the user
        $token = $user->createToken($request->email)->plainTextToken;

        return [
           'user' => $user,
           'token' => $token
        ];
    }

    public function logout(Request $request){
        // Get the authenticated user
        $user = $request->user();

        // Delete the user's token
        $user->tokens()->delete();

        return [
           'message' => 'Logged out successfully'
        ];

    }
}
