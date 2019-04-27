<?php

namespace App\Http\Controllers;

use Laravel\Lumen\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Request;

class AuthController extends BaseController
{
    /**
     * post: /login
     * @return string
     */
    public function postLogin(Request $req)
    {
        $credentials = $req->only('username', 'password');

        if ($token = $this->guard()->attempt($credentials)) {
            return $this->respondWithToken($token);
        }

        return response()->json( ['message' => 'Username or Password is wrong.'], 401);
    }

    /**
     * Log the user out (Invalidate the token)
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        $this->guard()->logout(true);

        return response()->json(['message' => 'Successfully logged out']);
    }

    /**
     * Refresh a token.
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        // Refreshed token oken comes as an auth header
        return response()->json();
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function respondWithToken($token)
    {
        return response()->json([
            '_id' => Auth::user()->_id,
            'email' => Auth::user()->email,
            'username' => Auth::user()->username,
            'first_name' => Auth::user()->first_name,
            'last_name' => Auth::user()->last_name,
            'token' => $token,
            // 'token_type' => 'bearer',
            'expires' => $this->guard()->factory()->getTTL() * 60,
            //  $this->guard()->user(),
            'roles' => $this->guard()->user()->roles()->pluck('name'),
        ])->header('Authorization', sprintf('Bearer %s', $token));
    }

    /**
     * Get the guard to be used during authentication.
     *
     * @return \Illuminate\Contracts\Auth\Guard
     */
    public function guard()
    {
        return Auth::guard();
    }
}
