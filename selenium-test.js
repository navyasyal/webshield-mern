
import { Builder, By, until } from "selenium-webdriver";
import chrome from "selenium-webdriver/chrome.js";

const BASE_URL = "https://webshield-mern.vercel.app/";

const email = process.env.WEBSHIELD_EMAIL;
const password = process.env.WEBSHIELD_PASSWORD;

async function runTests() {
  if (!email || !password) {
    console.log("FAIL: Set email and password environment variables.");
    process.exitCode = 1;
    return;
  }

  const options = new chrome.Options();
  options.addArguments("--start-maximized");

  const driver = await new Builder()
    .forBrowser("chrome")
    .setChromeOptions(options)
    .build();

  let passed = 0;
  let failed = 0;

  async function test(name, callback) {
    try {
      await callback();
      console.log(`PASS: ${name}`);
      passed++;
    } catch (error) {
      console.log(`FAIL: ${name} - ${error.message}`);
      failed++;
    }
  }

  try {
    console.log("\n===== WEBSHIELD END-TO-END TEST =====");

    await driver.get(BASE_URL);

    await driver.wait(
      until.elementLocated(By.css('input[type="email"]')),
      15000
    );

    await test("Website loaded", async () => {
      const title = await driver.getTitle();
      if (!title.includes("WebShield")) {
        throw new Error("Incorrect website title");
      }
    });

    await test("Email entered", async () => {
      const field = await driver.findElement(
        By.css('input[type="email"]')
      );
      await field.clear();
      await field.sendKeys(email);
    });

    await test("Password entered", async () => {
      const field = await driver.findElement(
        By.css('input[type="password"]')
      );
      await field.clear();
      await field.sendKeys(password);
    });

    await test("Sign In submitted", async () => {
      const button = await driver.findElement(
        By.xpath("//button[contains(.,'Sign In')]")
      );
      await button.click();
    });

    console.log("\nChecking authentication...");

    await driver.sleep(5000);

    const pageText = await driver.findElement(
      By.css("body")
    ).getText();

    const storage = await driver.executeScript(`
      return {
        local: Object.keys(localStorage),
        session: Object.keys(sessionStorage)
      };
    `);

    const currentUrl = await driver.getCurrentUrl();

    console.log("Current URL:", currentUrl);
    console.log("Storage keys:", JSON.stringify(storage));
    console.log("Visible page text:", pageText.slice(0, 1500));

    await test("Login response received", async () => {
      if (
        /invalid credentials|incorrect password|login failed/i.test(pageText)
      ) {
        throw new Error("Server rejected login credentials");
      }

      const hasSession =
        storage.local.length > 0 ||
        storage.session.length > 0;

      const dashboardVisible =
        /dashboard|new scan|scan history|security score|logout|sign out/i.test(
          pageText
        );

      const loginStillVisible =
        pageText.includes("WELCOME BACK") &&
        pageText.includes("Sign In Securely");

      if (loginStillVisible && !hasSession) {
        throw new Error("Authentication not confirmed");
      }

      if (!hasSession && !dashboardVisible) {
        throw new Error("No dashboard or authentication evidence found");
      }
    });

    await test("Dashboard or authenticated workspace visible", async () => {
      const dashboardVisible =
        /dashboard|new scan|scan history|security score|logout|sign out/i.test(
          pageText
        );

      const hasSession =
        storage.local.length > 0 ||
        storage.session.length > 0;

      if (!dashboardVisible && !hasSession) {
        throw new Error("Workspace not confirmed");
      }
    });

  } catch (error) {
    console.error("\nTEST ERROR:", error.message);
  } finally {
    console.log("\n===== FINAL TEST SUMMARY =====");
    console.log("Passed:", passed);
    console.log("Failed:", failed);
    console.log("Total:", passed + failed);

    await driver.quit();
  }

  if (failed > 0) process.exitCode = 1;
}

runTests();
