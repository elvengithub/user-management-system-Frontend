import { Injectable } from '@angular/core';
import { HttpRequest, HttpResponse, HttpHandler, HttpEvent, HttpInterceptor, HTTP_INTERCEPTORS, HttpHeaders } from '@angular/common/http';
import { Observable, of, throwError } from 'rxjs';
import { delay, materialize, dematerialize } from 'rxjs/operators';

import { AlertService } from '../../app/_services';
import { Role } from '../../app/_models';

const accountsKey = 'angular-10-signup-verification-boilerplate-accounts';
let accounts = JSON.parse(localStorage.getItem(accountsKey) || '[]');

@Injectable()
export class FakeBackendInterceptor implements HttpInterceptor {
    constructor(private alertService: AlertService) { }

    intercept(request: HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>> {
        const { url, method, headers, body } = request;
        const alertService = this.alertService;

        return handleRoute();

        function handleRoute() {
            switch (true) {
                case url.endsWith('/accounts/authenticate') && method === 'POST':
                    return authenticate();
                case url.endsWith('/accounts/refresh-token') && method === 'POST':
                    return refreshToken();
                case url.endsWith('/accounts/revoke-token') && method === 'POST':
                    return revokeToken();
                case url.endsWith('/accounts/register') && method === 'POST':
                    return register();
                case url.endsWith('/accounts/verify-email') && method === 'POST':
                    return verifyEmail();
                case url.endsWith('/accounts/forgot-password') && method === 'POST':
                    return forgotPassword();
                case url.endsWith('/accounts/validate-reset-token') && method === 'POST':
                    return validateResetToken();
                case url.endsWith('/accounts/reset-password') && method === 'POST':
                    return resetPassword();
                case url.endsWith('/accounts') && method === 'GET':
                    return getAccounts();
                case url.match(/\/accounts\/\d+$/) && method === 'GET':
                    return getAccountById();
                case url.endsWith('/accounts') && method === 'POST':
                    return createAccount();
                case url.match(/\/accounts\/\d+$/) && method === 'PUT':
                    return updateAccount();
                case url.match(/\/accounts\/\d+$/) && method === 'DELETE':
                    return deleteAccount();
                default:
                    return next.handle(request);
            }
        }

        // role functions

        function authenticate() {
            const { email, password } = body;
            const account = accounts.find(x => x.email === email);
        
            // First check if email exists
            if (!account) {
                setTimeout(() => {
                    alertService.error(
                        `<div style="color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
                            Email does not exist
                        </div>`,
                        { autoClose: false }
                    );
                }, 1000);
                return error('Email does not exist');
            }
        
            // Then check password
            if (account.password !== password) {
                return error('Incorrect Password');
            }
        
            // Check verification status
            if (!account.isVerified) {
                const verifyUrl = `${location.origin}/account/verify-email?token=${account.verificationToken}`;
                setTimeout(() => {
                    alertService.warn(
                        `<div style="color: #333; background-color: #f8f9fa; border: 1px solid #d6d8db; border-radius: 4px; padding: 15px; font-family: Arial, sans-serif;">
                            <div style="color: #0c5460; background-color: #17a2b8; border-color: #17a2b8; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
                                <h4>Email is not verified</h4>
                            </div>
                            <div style="color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
                                <p>Thanks for Registering!</p>
                                <p>Please click the below link to verify your email address:</p>
                            </div>
                            <p><a href="${verifyUrl}" style="color: #007bff;">${verifyUrl}</a></p>
                            <p><b>NOTE:</b> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</p>
                        </div>`,
                        { autoClose: false }
                    );
                }, 1000);
                return error('Email not verified');
            }
        
            // Add refresh token to account
            account.refreshTokens.push(generateRefreshToken());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
        
            return ok({
                ...basicDetails(account),
                jwtToken: generateJwtToken(account)
            });
        }


        function refreshToken() {
            const refreshToken = getRefreshToken();

            if (!refreshToken) return unauthorized();

            const account = accounts.find(x => x.refreshTokens.includes(refreshToken));

            if (!account) return unauthorized();

            // replace old refresh token with new one and save
            account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
            account.refreshTokens.push(generateRefreshToken());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok({
                ...basicDetails(account),
                jwtToken: generateJwtToken(account)
            });
        }

        function revokeToken() {
            if (!isAuthenticated()) return unauthorized();

            const refreshToken = getRefreshToken();
            const account = accounts.find(x => x.refreshTokens.includes(refreshToken));

            account.refreshTokens = account.refreshTokens.filter(x => x !== refreshToken);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function register() {
            const account = body;
        
            if (accounts.find(x => x.email === account.email)) {
                setTimeout(() => {
                    alertService.info(
                        `<div style="color: #333; background-color: #f8f9fa; border: 1px solid #d6d8db; border-radius: 4px; padding: 15px; font-family: Arial, sans-serif;">
                            <div style="color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
                                Email Already Registered
                            </div>
                            <p>Your email ${account.email} is already registered.</p>
                            <p>If you don't know your password please visit the <a href="${location.origin}/account/forgot-password" style="color: #007bff;">forgot password</a> page.</p>
                            <div style="margin-top: 10px; font-size: 0.9em; color: #6c757d;">
                                <strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.
                            </div>
                        </div>`,
                        { autoClose: false }
                    );
                }, 1000);
                return ok();
            }
        
            account.id = newAccountId();
            if (account.id === 1) {
                account.role = Role.Admin;
                account.isVerified = true;
                account.verificationToken = null;
            } else {
                account.role = Role.User;
                account.isVerified = false;
                account.verificationToken = new Date().getTime().toString();
            }
            account.dateCreated = new Date().toISOString();
            account.refreshTokens = [];
            delete account.confirmPassword;
            accounts.push(account);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
        
            if (account.id !== 1) {
                setTimeout(() => {
                    const verifyUrl = `${location.origin}/account/verify-email?token=${account.verificationToken}`;
                    alertService.info(
                        `<div style="color: #333; background-color: #f8f9fa; border: 1px solid #d6d8db; border-radius: 4px; padding: 15px; font-family: Arial, sans-serif;">
                            <h4 style="margin: 0 0 10px 0; color: #0c5460;">Verification Email</h4>
                            <p>Thanks for registering!</p>
                            <p>Please click the below link to verify your email address:</p>
                            <p style="margin: 15px 0; word-break: break-all;">
                                <a href="${verifyUrl}" style="color: #007bff; text-decoration: none;">${verifyUrl}</a>
                            </p>
                            <div style="margin-top: 15px; padding-top: 10px; border-top: 1px solid #eee; font-size: 0.9em; color: #6c757d;">
                                <strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.
                            </div>
                        </div>`,
                        { autoClose: false }
                    );
                }, 1000);
            } else {
                setTimeout(() => {
                    alertService.success(
                        `<div style="color: #333; background-color: #f8f9fa; border: 1px solid #d6d8db; border-radius: 4px; padding: 15px; font-family: Arial, sans-serif;">
                            <div style="color: #155724; background-color: #d4edda; border-color: #c3e6cb; padding: 10px; margin-bottom: 10px; border-radius: 4px;">
                                Admin registration successful. You can login directly.
                            </div>
                            <div style="font-weight: bold; margin-bottom: 10px;">First User Login</div>
                            <p>You can login directly as first user where role is Admin and account is verified</p>
                            <div style="margin-top: 10px; font-size: 0.9em; color: #6c757d;">
                                <strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.
                            </div>
                        </div>`,
                        { autoClose: false }
                    );
                }, 1000);
            }
        
            return ok();
        }
        
        function verifyEmail() {
            const { token } = body;
            
            // If token is empty, check if it's the first user trying to verify
            if (!token) {
                const firstUser = accounts.find(x => x.id === 1);
                if (firstUser) {
                    firstUser.isVerified = true;
                    localStorage.setItem(accountsKey, JSON.stringify(accounts));
                    return ok();
                }
                return error('Verification failed - no token provided');
            }
        
            // Normal token verification for subsequent users
            const account = accounts.find(x => !!x.verificationToken && x.verificationToken === token);
            if (!account) return error('Verification failed');
        
            account.isVerified = true;
            account.verificationToken = null;
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
        
            return ok();
        }

        function forgotPassword() {
            const { email } = body;
            const account = accounts.find(x => x.email === email);

            if (!account) return ok();

            account.resetToken = new Date().getTime().toString();
            account.resetTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            setTimeout(() => {
                const resetUrl = `${location.origin}/account/reset-password?token=${account.resetToken}`;
                alertService.info(
                    `<h4>Reset Password Email</h4>
                <p>Please click the below link to reset your password, the link will be valid for 1 day:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
                <div><strong>NOTE:</strong> The fake backend displayed this "email" so you can test without an api. A real backend would send a real email.</div>`,
                    { autoClose: false }
                );
            }, 1000);

            return ok();
        }

        function validateResetToken() {
            const { token } = body;
            const account = accounts.find(x =>
                !!x.resetToken &&
                x.resetToken === token &&
                new Date() < new Date(x.resetTokenExpires)
            );

            if (!account) return error('Invalid token');

            return ok();
        }

        // Additional methods would follow the same pattern...
        function resetPassword() {
            const { token, password } = body;
            const account = accounts.find(x =>
                !!x.resetToken &&
                x.resetToken === token &&
                new Date() < new Date(x.resetTokenExpires)
            );

            if (!account) return error('Invalid token');

            account.password = password;
            account.resetToken = null;
            account.resetTokenExpires = null;
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function getAccounts() {
            if (!isAuthenticated()) return unauthorized();

            return ok(accounts.map(x => basicDetails(x)));
        }

        function getAccountById() {
            if (!isAuthenticated()) return unauthorized();

            let account = accounts.find(x => x.id === idFromUrl());
            if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
                return unauthorized();
            }

            return ok(basicDetails(account));
        }


        function createAccount() {
            if (!isAuthorized(Role.Admin)) return unauthorized();

            const account = body;
            if (accounts.find(x => x.email === account.email)) {
                return error(`Email ${account.email} is already registered`);
            }

            account.id = newAccountId();
            account.dateCreated = new Date().toISOString();
            account.isVerified = true;
            account.refreshTokens = [];
            delete account.confirmPassword;
            accounts.push(account);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok();
        }

        function updateAccount() {
            if (!isAuthorized(Role.Admin)) return unauthorized();

            const params = body;
            let account = accounts.find(x => x.id === idFromUrl());

            if (account.id !== currentAccount() && !isAuthorized(Role.Admin)) {
                return unauthorized();
            }

            if (params.password) {
                delete params.password;
            }

            delete params.confirmPassword;

            Object.assign(account, params);
            localStorage.setItem(accountsKey, JSON.stringify(accounts));

            return ok(basicDetails(account));
        }

        function deleteAccount() {
            if (!isAuthenticated()) return unauthorized();

            let account = accounts.find(x => x.id === idFromUrl());

            //user accounts can delete own account and admin accounts can delete any account
            if (account.id !== currentAccount().id && !isAuthorized(Role.Admin)) {
                return unauthorized();
            }

            //delete account then save
            accounts = accounts.filter(x => x.id !== idFromUrl());
            localStorage.setItem(accountsKey, JSON.stringify(accounts));
            return ok();
        }

        // helper functions
        function ok(body?) {
            return of(new HttpResponse({ status: 200, body }))
                .pipe(delay(500)); //delay observable to simulate server api call
        }

        function error(message) {
            return throwError({ error: { message } })
                .pipe(materialize(), delay(500), dematerialize());
            //call materialize and dematerialize to ensure delay even if an error is thrown 
        }

        function unauthorized() {
            return throwError({ status: 401, error: { message: 'Unauthorized' } })
                .pipe(materialize(), delay(500), dematerialize());
        }

        function basicDetails(account) {
            const { id, title, firstName, lastName, email, role, dateCreated, isVerified } = account;
            return { id, title, firstName, lastName, email, role, dateCreated, isVerified };
        }

        function isAuthenticated() {
            return !!currentAccount();
        }

        function isAuthorized(role) {
            const account = currentAccount();
            if (!account) return false;
            return account.role === role;
        }

        function idFromUrl() {
            const urlParts = url.split('/');
            return parseInt(urlParts[urlParts.length - 1]);
        }

        function newAccountId() {
            return accounts.length ? Math.max(...accounts.map(x => x.id)) + 1 : 1;
        }

        function currentAccount() {
            // check if jwt token is in auth header
            const authHeader = headers.get('Authorization');
            if (!authHeader || !authHeader.startsWith('Bearer fake-jwt-token')) return;

            //check if token is expired
            const jwtToken = JSON.parse(atob(authHeader.split('.')[1]));
            const tokenExpired = Date.now() > (jwtToken.exp * 1000);
            if (tokenExpired) return;

            const account = accounts.find(x => x.id === jwtToken.id);
            return account;
        }

        function generateJwtToken(account) {
            // create token that expires in 15 minutes
            const tokenPayload = {
                exp: Math.round(new Date(Date.now() + 15 * 60 * 1000).getTime() / 1000),
                id: account.id,
            }
            return `fake-jwt-token.${btoa(JSON.stringify(tokenPayload))}`;
        }

        function generateRefreshToken() {
            const token = new Date().getTime().toString();

            // add token cookie that expires in 7 days
            const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toUTCString();
            document.cookie = `fakeRefreshToken=${token}; expires=${expires}; path=/`;

            return token;
        }

        function getRefreshToken() {
            // get refresh token from cookie
            return (document.cookie.split(';').find(x => x.includes('fakeRefreshToken')) || '=').split('=')[1];
        }

    }
}

export const fakeBackendProvider = {
    // use fake backend in place of Http service for backend-less development
    provide: HTTP_INTERCEPTORS,
    useClass: FakeBackendInterceptor,
    multi: true
};
