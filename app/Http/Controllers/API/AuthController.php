<?php

namespace App\Http\Controllers\API;

use Validator;
use App\Models\User;
use App\Http\Controllers\API\BaseController as BaseController;
use App\Http\Requests\TwoFactorLoginRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Laravel\Fortify\Events\RecoveryCodeReplaced;

class AuthController extends BaseController
{
    /**
     * Login API (with 2FA)
     * 
     * @return \Illuminate\Http\Response
     */
    public function signin(TwoFactorLoginRequest $request)
    {
        $user = User::where('email', $request->email)->firstOrFail();

        if ($user->hasTwoFactorEnabled()) {

            if ($code = $request->validRecoveryCode()) {
                $user->replaceRecoveryCode($code);

                event(new RecoveryCodeReplaced($user, $code));
            } elseif (!$request->hasValidCode()) {
                return $this->sendError('Unauthorised', ['error' => 'Invalid token']);
            }
        }

        if (Auth::attempt(['email' => $request->email, 'password' => $request->password])) {
            $authUser = Auth::user();
            $success['token'] = $authUser->createToken('MyAuthApp')->plainTextToken;
            $success['name'] = $authUser->name;

            return $this->sendResponse($success, 'User signed in');
        } else {
            return $this->sendError('Unauthorised.', ['error' => 'Unauthorised']);
        }
    }

    /**
     * Register API
     * 
     * @return \Illuminate\Http\Response
     */
    public function signup(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
            'confirm_password' => 'required|same:password',
        ]);

        if ($validator->fails()) {
            return $this->sendError('Error validation', $validator->errors());
        }

        $input = $request->all();
        $input['password'] = bcrypt($input['password']);
        $user = User::create($input);
        $success['token'] = $user->createToken('MyAuthApp')->plainTextToken;
        $success['name'] = $user->name;

        return $this->sendResponse($success, 'User created successfully.');
    }
}
