package org.bukkit.configuration.file;

public class FileConfiguration {
    public String getString(String path) { return null; }
    public String getString(String path, String def) { return def; }
    public int getInt(String path) { return 0; }
    public int getInt(String path, int def) { return def; }
    public boolean getBoolean(String path) { return false; }
    public boolean isSet(String path) { return false; }
}