<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\User;
use Hash;
use Illuminate\Support\Facades\Validator;
use JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;


class UserController extends Controller
{
    private $status_code = 200;
    
    public function login(Request $request) {
        $credentials = $request->only('email', 'password');
        $validator = Validator::make($request->all(),
            [
                "email"     =>  "required|email",
                "password"  =>  "required"
            ]
        );

        if($validator->fails()) {
            return response()->json(["status" => "failed", "validation_error" => $validator->errors()]);
        }

        // check if entered email exists in db
        $email_status       =       User::where("email", $request->email)->first();

        // if email exists then we will check password for the same email

        if(!is_null($email_status)) {
            // $password_status    =   User::where("email", $request->email)->where("password", md5($request->password))->first();

            // if password is correct
            try {
                if (! $token = JWTAuth::attempt($credentials)) {
                    return response()->json(["status" => "failed", "success" => false, "message" => "Unable to login. Incorrect password."]);
                }
            } catch (JWTException $e) {
                return response()->json(['error' => 'could_not_create_token'], 500);
            }

            $user = $this->userDetail($request->email);
            $user['token'] = $token;

            return response()->json(["status" => $this->status_code, "success" => true, "message" => "You have logged in successfully", "data" => $user]);

        }

        else {
            return response()->json(["status" => "failed", "success" => false, "message" => "Unable to login. Email doesn't exist."]);
        }
    }

    public function register(Request $request) {
        $validator = Validator::make($request->all(), [
          'firstname' => 'required',
          'lastname' => 'required',
          'email' => 'required',
          'password' => 'required',
          'city' => 'required',
          'country' => 'required',
          'birthdate' => 'required',
          'phone' => 'required',
        ]);

        if($validator->fails()) {
            return response()->json(["status" => "failed", "message" => "validation_error", "errors" => $validator->errors()]);
        }

        $userDataArray = array(
            "firstname" => $request->firstname,
            "lastname"  => $request->lastname,
            "birthdate" => $request->birthdate,
            "email"     => $request->email,
            "password"  => bcrypt($request->password),
            "phone"     => $request->phone,
            "city"      => $request->city,
            "country"   => $request->country
        );

        $user_status = User::where("email", $request->email)->first();

        if(!is_null($user_status)) {
           return response()->json(["status" => "failed", "success" => false, "message" => "Whoops! email already registered"]);
        }

        $user = User::create($userDataArray);

        if(!is_null($user)) {
            return response()->json(["status" => $this->status_code, "success" => true, "message" => "Registration completed successfully", "data" => $user]);
        }
        else {
            return response()->json(["status" => "failed", "success" => false, "message" => "failed to register"]);
        }
    }

    public function userDetail($email) {
        $user = array();
        if($email != "") {
            $user = User::where("email", $email)->first();
            return $user;
        }
    }

    public function index(Request $request)
    {
        $user = \App\User::query();

        if($request->get('filter')){
            if($request->get('keyword') && $request->get('filter') == 'Name'){
                $user = $user->where('firstname', 'like', '%' . $request->get('keyword'). '%');
            }
            if($request->get('keyword') && $request->get('filter') == 'Phone'){
                $user = $user->where('phone','like', '%' . $request->get('keyword'). '%');
            }
            if($request->get('keyword') && $request->get('filter') == 'City'){
                $user = $user->where('city','like', '%' . $request->get('keyword'). '%');
            }
            if($request->get('keyword') && $request->get('filter') == 'Country'){
                $user = $user->where('country','like', '%' . $request->get('keyword'). '%');
            }
        }

        $user = $user->paginate(10);
 
        return response()->json($user);
    }
 
    public function store(Request $request)
    {
        $validatedData = $request->validate([
          'firstname' => 'required',
          'lastname' => 'required',
          'email' => 'required',
          'password' => 'required',
          'city' => 'required',
          'country' => 'required',
          'birthdate' => 'required',
          'phone' => 'required',
        ]);

        if ($request->get('photo'))
        {
            $file      = $request->get('photo');
            $name = time().'.' . explode('/', explode(':', substr($file, 0, strpos($file, ';')))[1])[1];
            //move image to public/img folder
            \Image::make($request->get('photo'))->save(public_path('images/').$name);

            $project = \App\User::create([
                'firstname' => $validatedData['firstname'],
                'lastname' => $validatedData['lastname'],
                'email' => $validatedData['email'],
                'password' => bcrypt($validatedData['password']),
                'city' => $validatedData['city'],
                'country' => $validatedData['country'],
                'birthdate' => $validatedData['birthdate'],
                'phone' => $validatedData['phone'],
                'photo' => $name,
                'isAdmin' => request('isAdmin') ? request('isAdmin') : 0,
              ]);
        }
 
        $msg = [
            'success' => true,
            'message' => 'User created successfully!'
        ];
 
        return response()->json($msg);
    }
 
    public function getUser($id) // for edit and show
    {
        $user = \App\User::find($id);
 
        return $user->toJson();
    }
 
    public function update(Request $request, $id)
    {
        $validatedData = $request->validate([
            'firstname' => 'required',
            'lastname' => 'required',
            'email' => 'required',
            'password' => '',
            'city' => 'required',
            'country' => 'required',
            'birthdate' => 'required',
            'phone' => 'required',
        ]);
 
        $user = \App\User::find($id);
        $user->firstname = $validatedData['firstname'];
        $user->lastname = $validatedData['lastname'];
        $user->email = $validatedData['email'];
        
        if(!empty($validatedData['password'])){
          $user->password = bcrypt($validatedData['password']);  
        }

        if ($request->get('photo'))
        {
            $file      = $request->get('photo');
            $name = time().'.' . explode('/', explode(':', substr($file, 0, strpos($file, ';')))[1])[1];
            //move image to public/img folder
            \Image::make($request->get('photo'))->save(public_path('images/').$name);

            $user->photo = $name;
        }
        
        $user->city = $validatedData['city'];
        $user->country = $validatedData['country'];
        $user->birthdate = $validatedData['birthdate'];
        $user->phone = $validatedData['phone'];
        $user->isAdmin = request('isAdmin');
        $user->save();
 
        $msg = [
            'success' => true,
            'message' => 'User updated successfully'
        ];
 
        return response()->json($msg);
    }
 
    public function delete($id)
    {
        $user = \App\User::find($id);
        if(!empty($user)){
            $user->delete();
            $msg = [
                'success' => true,
                'message' => 'User deleted successfully!'
            ];
            return response()->json($msg);
        } else {
            $msg = [
                'success' => false,
                'message' => 'User deleted failed!'
            ];
            return response()->json($msg);
        }
    }

    public function getAuthenticatedUser()
    {
        try {

            if (! $user = JWTAuth::parseToken()->authenticate()) {
                return response()->json(['user_not_found'], 404);
            }

        } catch (Tymon\JWTAuth\Exceptions\TokenExpiredException $e) {

            return response()->json(['token_expired'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\TokenInvalidException $e) {

            return response()->json(['token_invalid'], $e->getStatusCode());

        } catch (Tymon\JWTAuth\Exceptions\JWTException $e) {

            return response()->json(['token_absent'], $e->getStatusCode());

        }

        return response()->json(compact('user'));
    }
}
