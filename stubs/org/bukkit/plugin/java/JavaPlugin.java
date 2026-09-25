package org.bukkit.plugin.java;

import java.io.File;
import java.io.InputStream;
import java.util.logging.Logger;

public abstract class JavaPlugin {
    public final File getDataFolder() { return new File("plugins/PerformanceBoost"); }
    public final Logger getLogger() { return Logger.getLogger("Minecraft"); }
    public final org.bukkit.configuration.file.FileConfiguration getConfig() { return null; }
    public void onEnable() {}
    public void onDisable() {}
}