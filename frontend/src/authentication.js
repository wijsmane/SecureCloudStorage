import { getAuth, signInWithPopup, GoogleAuthProvider } from "firebase/auth";

const auth = getAuth(); // initialise firebase authentication
const provider = new GoogleAuthProvider(); // set Google as provider

async function signInWithGoogle() {
    try {
        const result = await signInWithPopup(auth, provider);

        // get Google access token
        const credential = GoogleAuthProvider.credentialFromResult(result);
        const token = credential.accessToken; 

        const user = result.user;  // store user info

        // console.log("User Info:", user);
        // console.log("Access Token:", token);

        // verify token via backend
        const response = await fetch("/verify-token", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ idToken: token })
        });

        const data = await response.json(); // parse response
        console.log("Token verified on server:", data);

    } 
    catch (error) {
        console.error("Error during sign-in:", error);
    }
}