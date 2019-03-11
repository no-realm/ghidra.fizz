package ghidra.plugin.fizz;

import java.awt.BorderLayout;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.ScrollPaneConstants;

import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.util.InteriorSelection;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;

// @formatter:off
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "Fizz",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Signature Maker Plugin",
    description = "Signature Maker Plugin - by quosego <https://github.com/quosego>")
// @formatter:on

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 10, 2019
 */
public class FizzPlugin extends Plugin {
  private static final String PLUGIN_TITLE = "Fizz - Signature Maker Plugin";
  private static final String CONTEXT_GROUP = "Fizz";
  private static final String MENU_CONTEXT = "Fizz Signature";

  private DockingAction actionGhidraSignatureContext;

  private static final String CONTEXT_GHIDRA_OPTION_SELECTION =
      "Create a Ghidra Signature from Selection";
  private static final String[] SET_CONTEXT_GHIDRA_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_GHIDRA_OPTION_SELECTION
  };

  private DockingAction actionCommonSignatureContext;

  private static final String CONTEXT_COMMON_OPTION_SELECTION =
      "Create a Common Signature from Selection";
  private static final String[] SET_CONTEXT_COMMON_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_COMMON_OPTION_SELECTION
  };

  private DockingAction actionRawSignatureContext;

  private static final String CONTEXT_RAW_OPTION_SELECTION =
      "Create a RAW Signature from Selection";
  private static final String[] SET_CONTEXT_RAW_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_RAW_OPTION_SELECTION
  };

  public FizzPlugin(PluginTool tool) {
    super(tool);
    createActions();
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

  // ==================================================================================================
  // Action Provider methods
  // ==================================================================================================

  private void createActions() {
    int programSubMenuPosition = 1;

    // Ghidra Signature Context

    actionGhidraSignatureContext =
        new NavigatableContextAction(CONTEXT_GHIDRA_OPTION_SELECTION, getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createSignature(context.getNavigatable(), copySelection(context.getSelection()), ".");
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };

    MenuData menuGhidraData =
        new MenuData(
            new String[] {
              ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_GHIDRA_OPTION_SELECTION
            },
            CONTEXT_GROUP);
    menuGhidraData.setMenuSubGroup(Integer.toString(programSubMenuPosition++));
    actionGhidraSignatureContext.setMenuBarData(menuGhidraData);
    actionGhidraSignatureContext.setPopupMenuData(
        new MenuData(SET_CONTEXT_GHIDRA_POPUPPATH, CONTEXT_GROUP));
    actionGhidraSignatureContext.setKeyBindingData(
        new KeyBindingData(KeyEvent.VK_S, InputEvent.CTRL_DOWN_MASK));
    tool.addAction(actionGhidraSignatureContext);

    // Common Signature Context

    actionCommonSignatureContext =
        new NavigatableContextAction(CONTEXT_COMMON_OPTION_SELECTION, getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createSignature(context.getNavigatable(), copySelection(context.getSelection()), "??");
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };

    MenuData menuCommonData =
        new MenuData(
            new String[] {
              ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_COMMON_OPTION_SELECTION
            },
            CONTEXT_GROUP);
    menuCommonData.setMenuSubGroup(Integer.toString(programSubMenuPosition++));
    actionCommonSignatureContext.setMenuBarData(menuCommonData);
    actionCommonSignatureContext.setPopupMenuData(
        new MenuData(SET_CONTEXT_COMMON_POPUPPATH, CONTEXT_GROUP));
    actionCommonSignatureContext.setKeyBindingData(
        new KeyBindingData(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK));
    tool.addAction(actionCommonSignatureContext);

    // Raw Signature Context
    /*
        actionRawSignatureContext =
            new NavigatableContextAction(CONTEXT_COMMON_OPTION_SELECTION, getName()) {
              @Override
              protected void actionPerformed(NavigatableActionContext context) {
                createRawSignature(context.getNavigatable(), copySelection(context.getSelection()));
              }

              @Override
              protected boolean isEnabledForContext(NavigatableActionContext context) {
                return context.hasSelection() && context.getNavigatable().isVisible();
              }
            };

        MenuData menuRawData =
            new MenuData(
                new String[] {ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_RAW_OPTION_SELECTION},
                CONTEXT_GROUP);
        menuRawData.setMenuSubGroup(Integer.toString(programSubMenuPosition++));
        actionRawSignatureContext.setMenuBarData(menuRawData);
        actionRawSignatureContext.setPopupMenuData(
            new MenuData(SET_CONTEXT_RAW_POPUPPATH, CONTEXT_GROUP));
        actionRawSignatureContext.setKeyBindingData(
            new KeyBindingData(KeyEvent.VK_R, InputEvent.CTRL_DOWN_MASK));
        tool.addAction(actionRawSignatureContext);
    */

    // Fizz Context Menu

    tool.setMenuGroup(new String[] {MENU_CONTEXT}, CONTEXT_GROUP);
  }

  protected void setSelection(Navigatable navigatable, ProgramSelection selection) {
    if (navigatable == null) {
      GoToService service = tool.getService(GoToService.class);
      if (service == null) {
        // can't do anything
        return;
      }
      navigatable = service.getDefaultNavigatable();
    }
    navigatable.setSelection(selection);
  }

  private ProgramSelection copySelection(ProgramSelection selection) {
    if (selection != null) {
      InteriorSelection is = selection.getInteriorSelection();
      if (is != null) {
        InteriorSelection ih =
            new InteriorSelection(
                is.getFrom(), is.getTo(), is.getStartAddress(), is.getEndAddress());
        return new ProgramSelection(ih);
      }
    }
    return new ProgramSelection(selection);
  }

  protected void createSignature(
      Navigatable navigatable, ProgramSelection selection, String delimiter) {
    if (navigatable == null) {
      GoToService service = tool.getService(GoToService.class);
      if (service == null) {
        // can't do anything
        return;
      }
      navigatable = service.getDefaultNavigatable();
    }
    FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, delimiter);

    // Tiny UI

    JTextArea textArea = new JTextArea(5, 60);
    textArea.append(signature.getSignature());
    JPanel panel = new JPanel();
    panel.add(
        new JScrollPane(
            textArea,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED),
        BorderLayout.SOUTH);
    JOptionPane.showMessageDialog(
        null, panel, "Fizz - Obtained Signature:", JOptionPane.INFORMATION_MESSAGE);
  }

  protected void createRawSignature(Navigatable navigatable, ProgramSelection selection) {
    if (navigatable == null) {
      GoToService service = tool.getService(GoToService.class);
      if (service == null) {
        // can't do anything
        return;
      }
      navigatable = service.getDefaultNavigatable();
    }
    FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, "");

    // Tiny UI

    JTextArea textArea = new JTextArea(5, 60);
    textArea.append(signature.getRaw());
    textArea.append(signature.getSignature());
    JPanel panel = new JPanel();
    panel.add(
        new JScrollPane(
            textArea,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED),
        BorderLayout.SOUTH);
    JOptionPane.showMessageDialog(
        null, panel, "Fizz - Obtained Raw Signature:", JOptionPane.INFORMATION_MESSAGE);
  }
}
