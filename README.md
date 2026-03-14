# AUTHGO

Implementation of an Identity Provider (IdP) server written in Go. This project is a work in progress migration from a legacy Flask-based OAuth2 implementation.

The current codebase is in a functional boilerplate stage. Ongoing efforts are focused on:
 - Modular decoupling
 - Code documentation 
 - Refactoring

DPoP (Demonstrating Proof-of-Possession) is mandatory for all flows.

Supported Flows:

 - Authorization Code Flow (with PKCE and Confidential Clients).
 - Client Credentials Flow. (may be dismissed after client_assertion support)

To-do roadmap:
 - Implement PAR (Pushed Authorization Request) method. 
 - Implement client_assertion authentication.
 - Registration confirmation/otp on registration
 - Switch signing algorithms from ECDSA (ES256/512) to Ed25519 for better transparency (nothing-up-my-sleeve philosophy)
 - Migrate semi-stateful session tracking from MongoDB to Redis (SETEX) for his speed, automatic expiration (to avoid session buildup).
 - Transition from BRPOP/RPUSH to Redis Streams.
 - Optimize query indexing 
 - Add missing routes from the original Flask project:
	 - GET /devices (get a list of all active session and its corresponding
   User-Agent) 
	 - POST /revoke_devices (revoke all sessions or a specific one)     
	 - POST /introspect       
	 - POST /register_client - /register_client/{id}
 - Complete all missing react client routes


## ⚠️ IMPORTANT: OTP Worker Required

This authentication server implements a decoupled OTP (One-Time Password) verification system for both 2FA and password recovery. To complete the login flow and the password recovery flow, you must run a separate OTP worker. The server acts as a producer, delegating both delivery and validation logic to external services via Redis.
## Note on OTP lengths: 
  - Login(2FA): 6 Digits
  - Recover Password: 8 Digits 
 

## How it works:
### Login flow
 - OTP Generation & Delivery: Upon successful credential validation, the
   server pushes a message to the Redis list generate_otp. Your worker
   should consume this to send the code to the user (e.g., via Email or
   SMS). 
 - Verification Request: When a user submits the OTP, the server
   pushes a request to the Redis list verify_otp. 
 - Worker Processing: Your external worker must consume this message, verify the code, and
   manage rate-limiting/expiration logic. 
 - Response: The worker must RPush the result back to Redis using a specific temporary key:
   {queue_id}/{user_id}:{fingerprint}. The server waits for this
   response via BLPop with a 30-second timeout.

Expected Data Structures:

Message from Server (JSON on verify_otp list):
```JSON

{
  "user_id": "string",
  "otp": "string",
  "fingerprint": "string",
  "queue_id": "uuid"
}
```
Response from Worker (JSON on {queue_id}/{user_id}:{fingerprint} key):
```JSON
{
  "valid": true,
  "reason": "optional_error_code",
  "remaining_attempts": 3
}
```
## Password Recovery Flow:
  - Generation: Triggered by the /forgot-password endpoint. The server pushes to generate_recovery_otp. Your worker should generate an 8-digit code and send it.
  - Verification: Triggered during password reset. The server pushes to verify_recovery_otp.
  - Worker Response: The worker must RPush the result to RESPONSE/RECOVERY/{queue_id}. The server waits via BLPop (5s timeout, same data structure as 2FA response).
Message from Server (JSON on generate_recovery_otp):
```JSON 
{
  "queue_id": "uuid",
  "email": "string"
}
```
## Error Codes (reason field):
 - too_many_attempts: The session is immediately terminated.
 - expired_otp: The user is notified that the OTP is no longer valid.
 - Default: If valid is false, the system displays the remaining_attempts.

Note: If no worker responds within 30 seconds, the server will return a 500 Internal Server Error.

## How to Run it

### Prerequisites
- **Go** 
- **Node.js** & **pnpm** (for the React client)
- **Redis** & **MongoDB** (running and accessible)
- **OTP Worker**: Remember to have your worker listening on Redis (see "OTP Worker Required" above).
- **env files**: set the .env files in the client folder and in the root folder. (see the .env.example for examples)

### Start the project
Use the provided automation script to build the frontend and launch the server:

```bash
chmod +x run
./run

```

