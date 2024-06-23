import { CanActivate, ExecutionContext, Inject, Injectable } from "@nestjs/common";
import { AUTH_SERVICE } from "../constants/services";
import { ClientProxy } from "@nestjs/microservices";
import { Observable, catchError, map, of, tap } from "rxjs";

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(@Inject(AUTH_SERVICE) private readonly authClient: ClientProxy) {}

  canActivate(context: ExecutionContext): boolean | Promise<boolean> | Observable<boolean>{
    const jwt = context.switchToHttp().getRequest().cookies?.Authentication;
    if (!jwt) {
      return false;
    }
    return this.authClient.send('authenticate', {
      Authentication: jwt,
    }).pipe(
      tap((resp) => {
        context.switchToHttp().getRequest().user = resp;
      }),
      catchError(() => of(false)),
      map(() => true),
    );
  }
}