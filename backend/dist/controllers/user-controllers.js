import User from "../models/User.js";
export const getAllUsers = async () => {
    try {
        const users = await User.find();
    }
    catch (error) {
    }
};
//# sourceMappingURL=user-controllers.js.map