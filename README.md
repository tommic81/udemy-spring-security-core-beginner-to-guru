# Spring Security Core Beginner-to Guru

#### Application Security

- Spring Security provides: 
  - Protection from common security exploits 
  - Integration with external security products, such as LDAP 
  - Provides utilities for password encoding

##### Key Terms

- Identity - A unique actor, typically an individual aka user
- Credentials - Usually a user id and password
- Authentication - Is how the application verifies the identity of the requestor
  - Spring Security has a variety of methods for Authentication
  - Typically the user provides credentials, which are validated

- Authorization - Can a user perform an action?
  - Using the user’s identity, Spring Security determines if they are authorized to perform action

##### Authentication Providers

- Authentication Providers - Verify users identities
  -  Authentication Providers supported by Spring Security:
  -  In Memory
  -  JDBC / Database
  -  Custom
  - LDAP / Active Directory
  - Keycloak
  - ACL (Access Control List)
  - OpenID
  - CAS

##### Password Storage

- NoOp Password Encoder - plain text, not recommended - for legacy systems
- BCrypt - uses bcrypt password hashing
- Argon2 - Uses Argon2 algorithm
- Pbkdf2 - Uses PBKDF2 algorithm
- SCrypt - Uses scrypt algorithm
- Custom - Roll your own? Not recommended!

##### Spring Security Modules

- Core - Core modules of Spring Security
- Remoting - Only needed for support of RMI operations
- Web - Support of web applications
- Config - Provides support for XML and Java configuration
- LDAP - for integration with LDAP identity providers
- OAuth 2.0 Core - Core of OAuth 2.0 Authorization and OpenID
- OAuth 2.0 Client - Client support for OAuth 2.0 and OpenID clients
- OAuth 2.0 JOSE - Provides support for JOSE (Javascript Object Signing and Encryption)
- OAuth 2.0 Resource Server - Support for OAuth 2.0 Resource Servers
- ACL - Support for Access Control Lists
- CAS - Support for Central Authentication Service
- OpenID - Authenticate users with external OpenID server
- Test - Testing Support for Spring Security

#### Common Web Vulnerabilities

- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)

1. Injection - Injection of malicious code, such as SQL Injection attacks
   - Mitigation typically using proper encoding and bind variables

2. Broken Authentication - Authentication and session management implemented incorrectly
   - Mitigation - Use framework, don’t roll your own

3. Sensitive Data Exposure - Not protecting sensitive data
   - Mitigation - Proper error handling, don’t expose stack traces

4. XML External Entities- Poorly Configured XML Processors
   - Mitigation - Patch XML Processors frequently

5. Broken Access Control - User Restrictions not properly enforced
   - Mitigation - Automated Testing, verify restrictions

6. Security Misconfiguration - Unintentionally not protecting resources
   - Mitigation - Security Audits

7. CrossSite Scripting - XSS Allows Users to inject HTML or Javascript
   - Mitigation - Use proper validation and escaping

8. Insecure Deserialization - Insecure deserialization can allow remote code execution
   - Mitigation - Use open source, patch frequently

9. Using Components with Known Vulnerabilities - Popular components often have known vulnerabilities
   - Mitigation - Patch frequently

10. Insufficient Logging & Monitoring - Time to detect breaches often over 200 days
    - Mitigation - Properly monitor systems

#### Cross-site Scripting

- [Cross Site Scripting Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

- [Content Security Policy](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

#### Cross-Site Request Forgery - CSRF

- Auteticated user is redirected to the attaker's so he can stole credentials and use it to  request a real site 

- To protect from this attact String provides CRSF Token.

- The Synchronizer Token Pattern requires in addition to the session cookie, a secure random CSRF
  token must be in request

- CRSF Token must be part of HTTP Request not automatically sent by browser

  - Do not store CRSF token in cookies

  - Use:
    - HTTP Headers
    - Hidden Form Fields

- The SameSite cookie attribute can be set to tell browser to not send cookie when request is
  coming from other sites
-  SameSite cookie attribute is supported on all modern browsers, older browsers might not
  support
- Supports - None, Lax (~subdomain), Strict
- Modern browsers transitioning from None to Lax if not explicitly set.
- Should not solely rely on SameSite attribute for CSRF prevention

#### HTTP Basic Auth

- Two way to sumbit:
  - URL Encoding - https://username:password@www.example.com
  - HTTP Header - Key: Authorization, Value: Basic \<Base64 encoded string>
    - String - username:password

- Flaws
  - URL Encoding and Header Encoding are not secure
    - Trivial task to revert Base64 encoded string back to text value
  - To protect user credentials, use of HTTPS is recommended
  - HTTP Basic Authentication also criticized for sending user credentials in every request
    - Increases risk of compromise
    - Other methods send an authentication token in each request

- Spring by auto-configure HTTP Basic Authentication
  - Default User - user
    -  Set Property spring.security.user.name to override
  - Default Password - Random UUID, check console output
    - Set Property spring.security.user.password to override
  - All paths secured - except actuator info and health

##### Customizing user name and password

- application.properties

```properties
spring.security.user.name=spring
spring.security.user.password=guru
```

##### Integration test

```java
@WebMvcTest
public class BeerControllerIT {
    @Autowired
    WebApplicationContext wac;

    MockMvc mockMvc;

    @MockBean
    BeerRepository beerRepository;

    @MockBean
    BeerInventoryRepository beerInventoryRepository;

    @MockBean
    BreweryService breweryService;

    @MockBean
    CustomerRepository customerRepository;

    @MockBean
    BeerService beerService;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .webAppContextSetup(wac)
                .apply(springSecurity())
                .build();
    }

    @WithMockUser("spring")
    @Test
    void findBeers() throws Exception{
        mockMvc.perform(get("/beers/find"))
                .andExpect(status().isOk())
                .andExpect(view().name("beers/findBeers"))
                .andExpect(model().attributeExists("beer"));
    }
}

```

##### Testing HTTP Basic Auth

- BeerControllerIT.java

```java
    @Test
    void findBeersWithHttpBasic() throws Exception{
        mockMvc.perform(get("/beers/find").with(httpBasic("foo","bar")))
                .andExpect(status().isOk())
                .andExpect(view().name("beers/findBeers"))
                .andExpect(model().attributeExists("beer"));
    }
```

##### String Security Filter Chain

- https://spring.io/projects/spring-security#learn
- https://docs.spring.io/spring-security/site/docs/5.3.10.RELEASE/reference/html5/#servlet-security-filters

#### Spring Security Java Configuration

Permit All with URL Pattern Matching

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize.antMatchers("/", "/webjars/**", "/login", "/resources/**","/beers/find", "/beers*" ).permitAll();
                })
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }
}
```

##### Http Method Matching

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize.antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll();
                })
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }
}
```

##### Spring MVC Path Matchers

```java
   @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize.antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }
```

#### In Memory Authentication Provider

##### Spring Security Authentication Components

- Authentication Filter - A filter for a specific Authentication type in the Spring Security filter
  chain. (ie basic auth, remember me cookie, etc)
- Authentication Manager - Standard API interface used by filter
- Authentication Provider - The implementation of Authentication - (in memory, database, etc)
- User Details Service - Service to provide information about user
- Password Encoder - Service to encrypt and verify passwords
- Security Context - Holds details about authenticated entity
