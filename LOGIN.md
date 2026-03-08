Generate production-ready Spring Boot code for JWT authentication infrastructure using Spring Security.

Context
- I am building authentication with Spring Security + JWT.
- For now, implement only the security/authentication infrastructure.
- Actual login/signup business logic will be implemented later.
- Focus on clean architecture and code that can be directly added to a real project.

Requirements
- Use Spring Security
- Implement JWT authentication filter
- Implement stateless security configuration
- Passwords are stored using BCrypt
- Implement CustomUserDetails as a dedicated class
- Implement CustomUserDetailsService as a dedicated service
- Do not use inline/lambda-style temporary UserDetails implementation
- Do not implement OAuth2 now
- But keep the structure extensible for future OAuth2 support
- Login endpoint path: /api/v1/login
- Logout endpoint path: /api/v1/logout

Implement
- SecurityConfig
- JwtAuthenticationFilter
- JwtTokenProvider (or JwtUtil)
- CustomUserDetails
- CustomUserDetailsService
- AuthenticationEntryPoint for unauthorized requests
- AccessDeniedHandler for forbidden requests
- PasswordEncoder bean using BCrypt
- Minimal placeholder controller/service if needed
- Recommended package structure

Security behavior
- Use stateless session policy
- Disable csrf for REST API
- Permit unauthenticated access only where necessary
- Prepare /api/v1/login and /api/v1/logout paths in security config
- Apply JWT filter before UsernamePasswordAuthenticationFilter
- Extract JWT from Authorization header using Bearer token format
- Validate token and set Authentication into SecurityContextHolder
- If token is invalid, expired, or malformed, handle through proper exception flow

Code style
- Use clear class responsibilities
- Use constructor injection
- Use modern Spring Security style
- Avoid deprecated configuration style if possible
- Keep code minimal but production-oriented
- No unnecessary comments
- No mock/fake business logic beyond placeholders

Output format
- First show recommended package structure
- Then generate full code files with package declarations
- Ensure code is consistent and compilable in a standard Spring Boot project

Assume Spring Boot 3.x and Spring Security 6.x.
Do not implement signup logic or actual authentication business logic yet. Only create the infrastructure and placeholder interfaces/classes needed for future implementation.