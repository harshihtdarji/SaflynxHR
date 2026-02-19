import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import cors from "cors";
import whois from "whois-json";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const GOOGLE_API_KEY = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

/*Extract domain from URL*/

function extractDomain(url) {
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.hostname;
  } catch {
    return null;
  }
}

/* WHOIS lookup */

async function getWhois(domain) {
  try {
    return await whois(domain);
  } catch (error) {
    return { error: "WHOIS lookup failed" };
  }
}

app.post("/check-url", async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  const domain = extractDomain(url);
  if (!domain) {
    return res.status(400).json({ error: "Invalid URL" });
  }

  try {
    // 🔐 Google Safe Browsing check
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_API_KEY}`,
      {
        client: {
          clientId: "safe-url-check",
          clientVersion: "1.0.0",
        },
        threatInfo: {
          threatTypes: [
            "MALWARE",
            "SOCIAL_ENGINEERING",
            "UNWANTED_SOFTWARE",
            "POTENTIALLY_HARMFUL_APPLICATION",
          ],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url }],
        },
      }
    );

    const whoisData = await getWhois(domain);

    // ❌ Unsafe URL
    if (response.data.matches) {
      return res.json({
        safe: false,
        domain,
        threats: response.data.matches,
        whois: whoisData,
      });
    }

    // ✅ Safe URL
    res.json({
      safe: true,
      domain,
      message: "URL is safe",
      whois: whoisData,
    });

  } catch (error) {
    console.error(error.response?.data || error.message);
    res.status(500).json({ error: "Failed to check URL" });
  }
});

//chatgpt
app.get("/", (req, res) => {
  res.send("SaflynxHR Backend is Live 🚀");
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
