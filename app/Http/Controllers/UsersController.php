<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;

class UsersController extends Controller
{
    /**
     * Create a new UsersController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('jwt.verify', ['except' => ['login', 'register']]);
    }

    /**
     * Get list of users.
     *
     * @OA\Get(
     *     tags={"Users"},
     *     summary="Get list of users",
     *     description="Get list of users",
     *     path="/api/users/list",
     *     @OA\Response(response="201", description="User successfully signed out"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function index()
    {
        try {
            $data = User::join('users_address', 'users.id', '=', 'users_address.id_users')
            ->select(
                'users.*',
                'users_address.street',
                'users_address.city',
                'users_address.state',
                'users_address.number',
                'users_address.region',
                'users_address.complement'
            )->get();

            $return = array(
                'success' => false,
                'message' => 'Listed users',
                'data'    => $data
            );

            return response()->json($return);
        } catch (\Exception $e) {
            $return = array(
                'success' => false,
                'message' => $e->getMessage()
            );

            return response()->json($return, 500);
        }
    }
}
