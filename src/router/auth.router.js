const express = require("express");
const router = express.Router();

// Signup
router.post("/auth/signup");

// Email verification
router.post("/auth/verification-email");  
router.get("/auth/verification");         

// Login 
router.post("/auth/login");               
router.post("/auth/refresh");            
router.delete("/auth/logout");            

// Account updates
router.patch("/auth/password");          
router.patch("/auth/email");              
router.patch("/auth/username");           

// Password recovery
router.post("/auth/password/forgot");     
router.post("/auth/password/reset");      
router.post("/auth/password/resend");     

// User profile
router.get("/auth/me");                   
router.delete("/auth/me");                