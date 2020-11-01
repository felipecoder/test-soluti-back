<?php

namespace App\Http\Controllers;

use App\Models\User as ModelsUser;
use App\Models\UserAddress;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Validator;

class AuthController extends Controller
{
    /**
     * Create a new AuthController instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('jwt.verify', ['except' => ['login', 'register']]);
    }

    /**
     * Get a JWT via given credentials.
     *
     * @OA\Post(
     *     tags={"Auth"},
     *     summary="Return data user and bearer token",
     *     description="Return data user and bearer token",
     *     path="/api/auth/login",
     *     @OA\Parameter(
     *          in="header",
     *          name="email",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="email", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="password",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="password", type="string"))
     *     ),
     *     @OA\Response(response="201", description="Return data user and bearer token"),
     *     @OA\Response(response="422", description="Error validate data post"),
     *     @OA\Response(response="401", description="Unauthorized"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function login(Request $request)
    {
        try {
            $validator = Validator::make($request->all(), [
                'email'    => 'required|string',
                'password' => 'required|string|min:6',
            ]);

            if ($validator->fails()) {
                return response()->json($validator->errors(), 422);
            }

            if (!$token = auth()->attempt($validator->validated())) {
                return response()->json(['error' => 'Unauthorized'], 401);
            }

            $return = array(
                'success' => true,
                'message' => 'Login user successfully',
                'data'    => $this->createNewToken($token)
            );

            return response()->json($return, 201);
        } catch (\Exception $e) {
            $return = array(
                'success' => false,
                'message' => $e->getMessage()
            );

            return response()->json($return, 500);
        }
    }

    /**
     * Register a User.
     *
     * @OA\Post(
     *     tags={"Auth"},
     *     summary="Return message create user",
     *     description="Return message create user",
     *     path="/api/auth/register",
     *     @OA\Parameter(
     *          in="header",
     *          name="name",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="name", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="email",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="email", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="password",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="password", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="password_confirmation",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="password_confirmation", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="identity",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="identity", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="birthday",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="birthday", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="street",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="street", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="city",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="city", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="state",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="state", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="number",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="number", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="region",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="region", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="complement",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="complement", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="biometry",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="biometry", type="file"))
     *     ),
     *     @OA\Response(response="201", description="User successfully registered"),
     *     @OA\Response(response="400", description="Error validate data post"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function register(Request $request)
    {

        try {
            $validator = Validator::make($request->all(), [
                'name'       => 'required|string|between:2,100',
                'email'      => 'required|string|email|max:100|unique:users',
                'password'   => 'required|string|confirmed|min:6',
                'identity'   => 'required|string|between:11,14|unique:users',
                'birthday'   => 'required|date_format:Y-m-d|before:today',
                'street'     => 'required|string|max:255',
                'city'       => 'required|string|max:255',
                'state'      => 'required|string|max:255',
                'number'     => 'integer|nullable',
                'region'     => 'required|string|max:255',
                'complement' => 'string|nullable',
            ]);

            if ($validator->fails()) {
                $return = array(
                    'success' => false,
                    'message' => 'Error validation',
                    'data'    => $validator->errors()
                );

                return response()->json($return, 400);
            }

            if ($request->hasFile('biometry')) {
                if ($request->file('biometry')->isValid()) {

                    $file = $request->file('biometry');
                    $filename = md5(uniqid(rand(), true)).'.wsq';
                    $file->move(public_path().'/uploads/', $name = $filename);

                    $url = '/uploads/'.$filename;

                    // $extension = $request->biometry->extension();
                    // $request->biometry->storeAs('/', $validated['name'].".".$extension, 'public');
                    // $url = Storage::url($validated['name'].".".$extension);
                }else{
                    $return = array(
                        'success' => false,
                        'message' => 'Error upload 1'
                    );

                    return response()->json($return, 400);
                }
            }else{
                $return = array(
                    'success' => false,
                    'message' => 'Error upload 2'
                );

                return response()->json($return, 400);
            }

            if(!isset($url) || empty($url)){
                $return = array(
                    'success' => false,
                    'message' => 'Error upload 3'
                );

                return response()->json($return, 400);
            }

            DB::beginTransaction();

            $user_data = array(
                'name'              => $request->name,
                'email'             => $request->email,
                'email_verified_at' => now(),
                'password'          => bcrypt($request->password),
                'identity'          => $request->identity,
                'birthday'          => $request->birthday,
                'biometry'          => $url,
                'level'             => 1,
                'remember_token'    => Str::random(10),
            );

            $user = ModelsUser::create($user_data);

            $address_data = array(
                'id_users'   => $user->id,
                'street'     => $request->street,
                'city'       => $request->city,
                'state'      => $request->state,
                'number'     => $request->number,
                'region'     => $request->region,
                'complement' => $request->complement
            );

            $address = UserAddress::create($address_data);

            DB::commit();

            $data = array(
                'user'    => $user,
                'address' => $address
            );

            $return = array(
                'success' => true,
                'message' => 'User successfully registered',
                'data'    => $data
            );

            return response()->json($return, 201);
        } catch (\Exception $e) {

            DB::rollBack();

            $return = array(
                'success' => false,
                'message' => $e->getMessage()
            );

            return response()->json($return, 500);
        }
    }


    /**
     * Log the user out (Invalidate the token).
     *
     * @OA\Post(
     *     tags={"Auth"},
     *     summary="Logout user of system",
     *     description="Logout user of system",
     *     path="/api/auth/logout",
     *     @OA\Response(response="201", description="User successfully signed out"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function logout()
    {
        try {
            auth()->logout();

            $return = array(
                'success' => false,
                'message' => 'User successfully signed out'
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

    /**
     * Refresh a token.
     *
     * @OA\Post(
     *     tags={"Auth"},
     *     summary="Return new token user",
     *     description="Return new token user",
     *     path="/api/auth/refresh",
     *     @OA\Response(response="201", description="Return new token user"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function refresh()
    {
        try {
            $return = array(
                'success' => true,
                'message' => 'New token successfully registered',
                'data'    => $this->createNewToken(auth()->refresh())
            );

            return response()->json($return, 201);
        } catch (\Exception $e) {
            $return = array(
                'success' => false,
                'message' => $e->getMessage()
            );

            return response()->json($return, 500);
        }
    }

    /**
     * Get the authenticated User.
     *
     * @OA\Get(
     *     tags={"Auth"},
     *     summary="Return user data",
     *     description="Return user data",
     *     path="/api/auth/user-profile",
     *     @OA\Response(response="201", description="Return user data"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function userProfile()
    {
        try {

            $user    = auth()->user();
            $address = UserAddress::where('id_users', $user->id)->first();

            $data = array(
                'user'    => $user,
                'address' => $address
            );

            $return = array(
                'success' => true,
                'message' => 'Get user successfully',
                'data'    => $data
            );

            return response()->json($return, 201);
        } catch (\Exception $e) {
            $return = array(
                'success' => false,
                'message' => $e->getMessage()
            );

            return response()->json($return, 500);
        }
    }

    /**
     * Get the token array structure.
     *
     * @param  string $token
     *
     * @return \Illuminate\Http\JsonResponse
     */
    protected function createNewToken($token)
    {
        return array(
            'access_token' => $token,
            'token_type'   => 'bearer',
            'expires_in'   => auth()->factory()->getTTL() * 60,
            'user'         => auth()->user()
        );
    }

    /**
     * Update User.
     *
     * @OA\Post(
     *     tags={"Auth"},
     *     summary="Return message update user",
     *     description="Return message update user",
     *     path="/api/auth/update",
     *     @OA\Parameter(
     *          in="header",
     *          name="name",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="name", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="password",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="password", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="password_confirmation",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="password_confirmation", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="birthday",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="birthday", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="street",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="street", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="city",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="city", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="state",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="state", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="number",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="number", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="region",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="region", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="complement",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="complement", type="string"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="biometry",
     *          required=true,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="biometry", type="file"))
     *     ),
     *     @OA\Parameter(
     *          in="header",
     *          name="current_password",
     *          required=false,
     *          style="form",
     *          @OA\Schema(@OA\Property(property="current_password", type="string"))
     *     ),
     *     @OA\Response(response="201", description="User successfully registered"),
     *     @OA\Response(response="400", description="Error validate data post"),
     * ),
     *
     * @return \Illuminate\Http\JsonResponse
     */
    public function update(Request $request)
    {

        try {
            $validator = Validator::make($request->all(), [
                'name'             => 'required|string|between:2,100',
                'password'         => 'string|nullable|confirmed|min:6',
                'birthday'         => 'required|date_format:Y-m-d|before:today',
                'street'           => 'required|string|max:255',
                'city'             => 'required|string|max:255',
                'state'            => 'required|string|max:255',
                'number'           => 'integer|nullable',
                'region'           => 'required|string|max:255',
                'complement'       => 'string|nullable',
                'current_password' => 'required|string|max:255',
            ]);

            if ($validator->fails()) {
                $return = array(
                    'success' => false,
                    'message' => 'Error validation',
                    'data'    => $validator->errors()
                );

                return response()->json($return, 400);
            }

            $user    = auth()->user();
            $address = UserAddress::where('id_users', $user->id)->first();

            if (!Hash::check($request->current_password, $user->password)) {
                $return = array(
                    'success' => false,
                    'message' => 'Password not match'
                );

                return response()->json($return, 400);
            }

            if ($request->hasFile('biometry')) {
                if ($request->file('biometry')->isValid()) {

                    $file = $request->file('biometry');
                    $filename = md5(uniqid(rand(), true)).'.wsq';
                    $file->move(public_path().'/uploads/', $name = $filename);

                    $url = '/uploads/'.$filename;
                }else{
                    $return = array(
                        'success' => false,
                        'message' => 'Error upload 1'
                    );

                    return response()->json($return, 400);
                }
            }

            DB::beginTransaction();

            $user_data = array(
                'name'     => $request->name,
                'password' => (!empty($request->password)) ? bcrypt($request->password) : $user->password,
                'identity' => (!empty($request->identity)) ? $request->identity : $user->identity,
                'birthday' => $request->birthday,
                'biometry' => (isset($url) and !empty($url)) ? $url : $user->biometry,
            );

            $user_update = ModelsUser::where('id', $user->id)->update($user_data);

            $address_data = array(
                'id_users'   => $user->id,
                'street'     => $request->street,
                'city'       => $request->city,
                'state'      => $request->state,
                'number'     => (!empty($request->number)) ? $request->number : $address->number,
                'region'     => $request->region,
                'complement' => (!empty($request->complement)) ? $request->complement : $address->complement,
            );

            $address_update = UserAddress::where('id', $address->id)->update($address_data);

            DB::commit();

            $return = array(
                'success' => true,
                'message' => 'User successfully updated'
            );

            return response()->json($return, 201);
        } catch (\Exception $e) {

            DB::rollBack();

            $return = array(
                'success' => false,
                'message' => $e->getMessage()
            );

            return response()->json($return, 500);
        }
    }
}
