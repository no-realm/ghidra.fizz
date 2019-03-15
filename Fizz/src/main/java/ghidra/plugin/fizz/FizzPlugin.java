package ghidra.plugin.fizz;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;

// @formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "Fizz",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Signature Maker Plugin",
    description = "Signature Maker Plugin - by quosego 'https://github.com/quosego'")
// @formatter:on

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 15, 2019
 */
public class FizzPlugin extends Plugin {
  private static final String PLUGIN_TITLE = "Fizz - Signature Maker Plugin";
  private FizzContext context;

  public FizzPlugin(PluginTool tool) {
    super(tool);
    context = new FizzContext(tool);
  }

  public String getTitle() {
    return PLUGIN_TITLE;
  }

  @Override
  public void init() {
    super.init();
  }

  @Override
  protected void dispose() {
    super.dispose();
  }
}
