// controllers/message.controller.js
import User from "../models/user.model.js";
import Message from "../models/message.model.js";
import cloudinary from "../lib/cloudinary.js";
import { io } from "../lib/socket.js"; // ensure lib/socket.js exports `io`

const safeUserId = (user) => user?.id || user?._id || null;

export const getUsersForSidebar = async (req, res) => {
  try {
    const loggedInUserId = safeUserId(req.user);
    if (!loggedInUserId) return res.status(401).json([]); // return array to keep UI stable

    const users = await User.find({ _id: { $ne: loggedInUserId } })
      .select("-password")
      .lean();

    // Optionally add `online` flag here if you export a socket helper; for now return plain users
    return res.status(200).json(users);
  } catch (error) {
    console.error("Error in getUsersForSidebar:", error);
    // Return empty array on error to avoid client crash (frontend can show empty state)
    return res.status(500).json([]);
  }
};

export const getMessages = async (req, res) => {
  try {
    const userToChatId = req.params.id;
    const myId = safeUserId(req.user);
    if (!myId) return res.status(401).json([]);
    if (!userToChatId) return res.status(400).json([]);

    const messages = await Message.find({
      $or: [
        { senderId: myId, receiverId: userToChatId },
        { senderId: userToChatId, receiverId: myId },
      ],
    })
      .sort({ createdAt: 1 })
      .lean();

    return res.status(200).json(messages); // array root
  } catch (error) {
    console.error("Error in getMessages controller:", error);
    return res.status(500).json([]);
  }
};

export const sendMessage = async (req, res) => {
  try {
    const { text, image } = req.body || {};
    const receiverId = req.params.id;
    const senderId = safeUserId(req.user);

    if (!senderId) return res.status(401).json({ ok: false, error: "Unauthorized" });
    if (!receiverId) return res.status(400).json({ ok: false, error: "Missing receiver id" });
    if ((!text || !text.trim()) && !image) {
      return res.status(400).json({ ok: false, error: "Text or image required" });
    }

    let imageUrl = null;
    if (image) {
      try {
        const uploadResponse = await cloudinary.uploader.upload(image);
        imageUrl = uploadResponse.secure_url;
      } catch (uploadErr) {
        console.error("Cloudinary upload error:", uploadErr);
        return res.status(500).json({ ok: false, error: "Image upload failed" });
      }
    }

    const newMessage = await Message.create({
      senderId,
      receiverId,
      text: text ? text.trim() : "",
      image: imageUrl,
    });

    // Emit to the recipient room in /chat namespace (room name = userId)
    try {
      io.of("/chat").to(String(receiverId)).emit("newMessage", newMessage);
      // echo to sender's room so sender UI can update in realtime
      io.of("/chat").to(String(senderId)).emit("messageSent", newMessage);
    } catch (emitErr) {
      console.warn("Failed to emit message via socket:", emitErr);
      // do not fail the API for emit errors
    }

    // Return the saved message object directly
    return res.status(201).json(newMessage);
  } catch (error) {
    console.error("Error in sendMessage controller:", error);
    return res.status(500).json({ ok: false, error: "Internal server error" });
  }
};
