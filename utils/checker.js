const axios = require("axios");
const sslChecker = require("ssl-checker");
const whois = require("whois-json");

async function checkDomainExpiry(domain) {
  try {
    const data = await whois(domain);
    console.log("WHOIS data:", data);

    // key ยอดนิยมที่เก็บวันหมดอายุ
    const expiryStr =
      data.expDate ||
      data['Registrar Registration Expiration Date'] ||
      data['Registry Expiry Date'] ||
      data['Expiration Date'];

    if (expiryStr) {
      const expiryDate = new Date(expiryStr);
      return { expiryDate, expired: expiryDate < new Date() };
    } else {
      return { expiryDate: null, expired: null, error: "Expiry date not found" };
    }
  } catch (error) {
    return { expiryDate: null, expired: null, error: error.message };
  }
}

async function checkWebsite(url) {
  const start = Date.now();
  let status = "down";
  let responseTime = null;
  let sslExpired = null;
  let sslExpiryDate = null;
  let sslDaysRemaining = null;
  let domainExpiryDate = null;
  let domainExpired = null;

  try {
    const response = await axios.get(url);
    const duration = Date.now() - start;
    status = response.status === 200 ? "up" : "down";
    responseTime = duration;

    // ดึง hostname จาก url
    const domain = url.replace(/^https?:\/\//, "").replace(/\/.*$/, "");

    // ตรวจสอบ SSL certificate
    const { daysRemaining, valid } = await sslChecker(domain, {
      method: "GET",
      port: 443,
    });
    sslExpired = !valid;
    sslDaysRemaining = daysRemaining;

    if (typeof daysRemaining === "number") {
      const now = new Date();
      sslExpiryDate = new Date(now.getTime() + daysRemaining * 24 * 60 * 60 * 1000);
    }

    // ตรวจสอบวันหมดอายุโดเมน
    const domainCheck = await checkDomainExpiry(domain);
    domainExpiryDate = domainCheck.expiryDate;
    domainExpired = domainCheck.expired;

    return {
      status,
      responseTime,
      sslExpired,
      sslExpiryDate,
      sslDaysRemaining,
      domainExpiryDate,
      domainExpired,
    };
  } catch (err) {
    console.log(err);
    return {
      status: "down",
      responseTime: null,
      sslExpired: null,
      sslExpiryDate: null,
      sslDaysRemaining: null,
      domainExpiryDate: null,
      domainExpired: null,
    };
  }
}

module.exports = { checkWebsite };
