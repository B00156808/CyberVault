import { app, BrowserWindow } from 'electron';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
// __dirname equivalent for ES module context
const __dirname = path.dirname(fileURLToPath(import.meta.url));
let mainWindow = null;
function createWindow() {
    mainWindow = new BrowserWindow({
        width: 800,
        height: 600,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false, // Keep nodeIntegration off for security
        },
    });
    // Get the correct path to the React build
    const reactBuildPath = path.join(__dirname, '..', 'dist-react', 'index.html');
    console.log("🚀 Loading file:", reactBuildPath);
    // Check if the file exists before trying to load it
    if (fs.existsSync(reactBuildPath)) {
        console.log("✅ React build found. Loading...");
        mainWindow.loadFile(reactBuildPath);
    }
    else {
        console.error("❌ ERROR: React build NOT FOUND at:", reactBuildPath);
    }
    mainWindow.on('closed', () => {
        mainWindow = null;
    });
}
// When Electron is ready, create the window
app.whenReady().then(createWindow);
// Quit when all windows are closed (except on macOS)
app.on('window-all-closed', () => {
    if (process.platform !== 'darwin') {
        app.quit();
    }
});
// Recreate window when clicking the app icon (macOS behavior)
app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
    }
});
