const functions = require("firebase-functions");
const admin = require("firebase-admin");
admin.initializeApp();

exports.setUserRole = functions.https.onCall(async (data, context) => {
  // Check if the user calling the function is authenticated and is an admin.
  if (!context.auth || context.auth.token.role !== "admin") {
    throw new functions.https.HttpsError(
      "permission-denied",
      "Only admins can assign roles."
    );
  }

  const { email, role } = data;

  // Validate that the email and role are provided and are valid.
  if (!email || !["admin", "staff", "customer"].includes(role)) {
    throw new functions.https.HttpsError(
      "invalid-argument",
      "The function must be called with a valid email and role."
    );
  }

  try {
    const user = await admin.auth().getUserByEmail(email);
    await admin.auth().setCustomUserClaims(user.uid, { role: role });

    // Force a new token to be issued on the client.
    await admin.auth().revokeRefreshTokens(user.uid);

    return { message: `Success! Role '${role}' assigned to ${email}.` };
  } catch (error) {
    throw new functions.https.HttpsError(
      "internal",
      "Failed to assign role.",
      error
    );
  }
});