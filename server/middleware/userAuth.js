import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.status(401).json({
            success: false,
            message: "Please log in again.",
        });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_KEY);

        if (decoded.id) {
            req.body.userId = decoded.id;
        } else {
            return res.status(400).json({
                success: false,
                message: "Invalid user ID in token.",
            });
        }

        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: "Authentication failed. " + error.message,
        });
    }
};

export default userAuth;
