# **libreriaGaia-Frontend:** Cliente angular-oauth2-oidc

Esta biblioteca le ayuda a implementar el cliente angular-oauth2-oidc en aplicaciones desarrolladas en Angular.

## Colaboradores

- https://github.com/JBOLGAR83
- https://github.com/Tartessus
- https://github.com/llopcas
- https://github.com/raca1487
- https://github.com/jrodg85

## Instalación en angular:

```
npm i angular-oauth2-oidc-jwks --save
```

## Importar el NgModule:

```
import { HttpClientModule } from '@angular/common/http';
import { OAuthModule } from 'angular-oauth2-oidc';
// etc.

@NgModule({
  imports: [
    // etc.
    HttpClientModule,
    OAuthModule.forRoot()
  ],
  declarations: [
    AppComponent,
    HomeComponent,
    // etc.
  ],
  bootstrap: [
    AppComponent
  ]
})
export class AppModule {
}

```
## Configurar el Logging

```
 import { AuthConfig } from 'angular-oauth2-oidc';

  export const authCodeFlowConfig: AuthConfig = {
    // Url del servidor de Gaia
    issuer: 'https://idsvr4.azurewebsites.net',

    // URL de la pagina de inicio a redirigir despues del login
    redirectUri: window.location.origin + '/index.html',

    // Id de cliente
    clientId: 'spa',

    // Secret del cliente si lo tuviera
    dummyClientSecret: 'secret',

    responseType: 'code',

    // Para OIDC por defecto el scope son: openid profile email offline_access
    // El token de refresco se consigue con offline_access
    // api es un caso de uso específico
    scope: 'openid profile email offline_access api',

    showDebugInformation: true,
  };
```

## Inicializar el codigo de autenticación en la API

```
this.oauthService.initCodeFlow();
```

## Logging out

```
this.oauthService.logOut();
```

## Revocar Token

```
this.oauthService.revokeTokenAndLogout();
```

## Llamada al back con access token

```
OAuthModule.forRoot({
    resourceServer: {
        allowedUrls: ['http://www.angular.at/api'],
        sendAccessToken: true
    }
})
```
## Securización de rutas

```
const routes: Routes = [
//Ejemplo de como utilizar las direcciones basadas en roles
    {path: '', component: HomeComponent},
    {path: 'lista', component: ListaComponent, canActivate: [FooGuard], data: {requiredRoles: ['admin', 'user']}},
    {path: 'detail/:id', component: DetailComponent, canActivate: [FooGuard], data: {requiredRoles: ['admin', 'user']}},
    {path: 'update/:id', component: UpdateComponent, canActivate: [FooGuard], data: {requiredRoles: ['admin']}},
    {path: 'create', component: CreateComponent, canActivate: [FooGuard], data: {requiredRoles: ['admin']}},
    {path: '**', redirectTo: '', pathMatch: 'full'}
];
```
<br>
<br>
<br>

# **libreriaGaia-Frontend:** Cliente Keycloak-angular y keycloak-js

Esta biblioteca le ayuda a implementar el cliente Keycloak-angular y keycloak-js en aplicaciones desarrolladas en Angular.

## Instalación en angular:

```
npm install keycloak-angular keycloak-js
```

## Función APP_INITALIZER:

   - Implementará por defecto una llamada al servidor de autenticación con los datos de url, nombre del REALM, y client id:

```
import { APP_INITIALIZER, NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { KeycloakAngularModule, KeycloakService } from 'keycloak-angular';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
 
function initializeKeycloak(keycloak: KeycloakService) {
  return () =>
    keycloak.init({
      config: {
        url: 'http://localhost:8080/auth',
        realm: 'your-realm',
        clientId: 'your-client-id',
      },
      initOptions: {
        onLoad: 'check-sso',
        silentCheckSsoRedirectUri:
          window.location.origin + '/assets/silent-check-sso.html',

          // Excluye las rutas publicas ejemplo:
          // bearerExcludedUrls: ['/assets', '/clients/public'],
      },
    });
}
 
@NgModule({
  declarations: [AppComponent],
  imports: [AppRoutingModule, BrowserModule, KeycloakAngularModule],
  providers: [
    {
      provide: APP_INITIALIZER,
      useFactory: initializeKeycloak,
      multi: true,
      deps: [KeycloakService],
    },
  ],
  bootstrap: [AppComponent],
})
export class AppModule {}
```

## Función AUTHGUARD:

   - Protege las rutas autenticadas en la aplicación, pudiendo acceder a ellas en función de los roles de la API.

```
import { Injectable } from '@angular/core';
import {
  ActivatedRouteSnapshot,
  Router,
  RouterStateSnapshot,
} from '@angular/router';
import { KeycloakAuthGuard, KeycloakService } from 'keycloak-angular';
 
@Injectable({
  providedIn: 'root',
})
export class AuthGuard extends KeycloakAuthGuard {
  constructor(
    protected readonly router: Router,
    protected readonly keycloak: KeycloakService
  ) {
    super(router, keycloak);
  }
 
  public async isAccessAllowed(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ) {
    // Fuerza la autenticacon al acceder al recurso si no esta atenticado
    if (!this.authenticated) {
      await this.keycloak.login({
        redirectUri: window.location.origin + state.url,
      });
    }
 
    // Define los roles necesarios para acceder a la ruta
    const requiredRoles = route.data.roles;
 
    // Permite que el usuario continue si no se requieren roles adicionales para acceder a la ruta.
    if (!(requiredRoles instanceof Array) || requiredRoles.length === 0) {
      return true;
    }
 
    // Permite continuar al usuario si dispone de todos los roles requeridos
    return requiredRoles.every((role) => this.roles.includes(role));
  }
}
```

