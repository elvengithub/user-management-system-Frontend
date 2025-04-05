import {Injectable} from '@angular/core';
import {HttpRequest, HttpHandler,HttpEvent,HttpInterecptor} from '@angular/common/http';
import{Observable}  from 'rxjs';

import{environment} from '@environments/environment';
import { AccountService} from '@app/_services';


@Injectable()
export class JwtInterceptor implements HttpInterecptor{
    constructor(private accountService : AccountService){   }

    intecept(request:HttpRequest<any>, next: HttpHandler): Observable<HttpEvent<any>>{
        // add auth header with jwt if acount is logged in and request is to the api url
        const account = this.accountService.accountValue;
        const isLogggedIn = account && account.jwtToken;
        const isApiUrl = request.url.startsWith(environment.ApiUrl);
        if (isLogggedIn && isApiUrl){
            request = request.clone({
                setHeaders:{Authorization :`Bearer ${account.jwtToken}`}
            }); 
        }

        return next.handle(request);
    }
}