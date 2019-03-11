package ghidra.plugin.fizz;

import docking.action.DockingAction;
import docking.action.KeyBindingData;
import docking.action.MenuData;
import ghidra.app.context.NavigatableActionContext;
import ghidra.app.context.NavigatableContextAction;
import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.ToolConstants;
import ghidra.program.util.InteriorSelection;
import ghidra.program.util.ProgramSelection;

import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 11, 2019
 */
class FizzContext {
  private PluginTool tool;
  private static int programSubMenuPosition = 1;

  private static final String CONTEXT_GROUP = "Fizz";
  private static final String MENU_CONTEXT = "Fizz Signature";

  //
  private static final String CONTEXT_GHIDRA_OPTION_SELECTION =
      "Create a Ghidra Signature from Selection";
  private static final String[] SET_CONTEXT_GHIDRA_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_GHIDRA_OPTION_SELECTION
  };
  private static final String[] SET_CONTEXT_GHIDRA_SELECTION = {
    ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_GHIDRA_OPTION_SELECTION
  };

  //
  private static final String CONTEXT_COMMON_OPTION_SELECTION =
      "Create a Common Signature from Selection";
  private static final String[] SET_CONTEXT_COMMON_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_COMMON_OPTION_SELECTION
  };
  private static final String[] SET_CONTEXT_COMMON_SELECTION = {
    ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_COMMON_OPTION_SELECTION
  };

  //
  private static final String CONTEXT_RAW_OPTION_SELECTION =
      "Create a RAW Signature from Selection";
  private static final String[] SET_CONTEXT_RAW_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_RAW_OPTION_SELECTION
  };
  private static final String[] SET_CONTEXT_RAW_SELECTION = {
    ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_RAW_OPTION_SELECTION
  };

  FizzContext(PluginTool tool) {
    this.tool = tool;
    createActions();
  }

  // =============================================================================================
  // Docking Action helper
  // =============================================================================================

  private void createDockingAction(DockingAction action, String[] selection, String[] popup) {
    MenuData menuData = new MenuData(selection, CONTEXT_GROUP);
    menuData.setMenuSubGroup(Integer.toString(programSubMenuPosition++));
    action.setMenuBarData(menuData);
    action.setPopupMenuData(new MenuData(popup, CONTEXT_GROUP));
  }

  // =============================================================================================
  // Action Provider methods
  // =============================================================================================

  private void createActions() {
    createGhidraSignatureContext();
    createCommonSignatureContext();
    createRawSignatureContext();
    tool.setMenuGroup(new String[] {MENU_CONTEXT}, CONTEXT_GROUP);
  }

  private void createGhidraSignatureContext() {
    DockingAction actionGhidraSignatureContext =
        new NavigatableContextAction(CONTEXT_GHIDRA_OPTION_SELECTION, this.tool.getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createSignature(context.getNavigatable(), copySelection(context.getSelection()), ".");
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };
    createDockingAction(
        actionGhidraSignatureContext, SET_CONTEXT_GHIDRA_SELECTION, SET_CONTEXT_GHIDRA_POPUPPATH);

    actionGhidraSignatureContext.setKeyBindingData(
        new KeyBindingData(KeyEvent.VK_G, InputEvent.ALT_DOWN_MASK));
    tool.addAction(actionGhidraSignatureContext);
  }

  private void createCommonSignatureContext() {
    DockingAction actionCommonSignatureContext =
        new NavigatableContextAction(CONTEXT_COMMON_OPTION_SELECTION, this.tool.getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createSignature(context.getNavigatable(), copySelection(context.getSelection()), "??");
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };
    createDockingAction(
        actionCommonSignatureContext, SET_CONTEXT_COMMON_SELECTION, SET_CONTEXT_COMMON_POPUPPATH);

    actionCommonSignatureContext.setKeyBindingData(
        new KeyBindingData(KeyEvent.VK_V, InputEvent.ALT_DOWN_MASK));
    tool.addAction(actionCommonSignatureContext);
  }

  private void createRawSignatureContext() {
    DockingAction actionRawSignatureContext =
        new NavigatableContextAction(CONTEXT_COMMON_OPTION_SELECTION, this.tool.getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createRawSignature(context.getNavigatable(), copySelection(context.getSelection()));
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };

    createDockingAction(
        actionRawSignatureContext, SET_CONTEXT_RAW_SELECTION, SET_CONTEXT_RAW_POPUPPATH);

    actionRawSignatureContext.setKeyBindingData(
        new KeyBindingData(KeyEvent.VK_D, InputEvent.ALT_DOWN_MASK));
    tool.addAction(actionRawSignatureContext);
  }

  // =============================================================================================
  // Action Listener methods
  // =============================================================================================

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

  private Navigatable getNavigatableProgram(Navigatable navigatable) {
    if (navigatable == null) {
      GoToService service = tool.getService(GoToService.class);
      if (service == null) {
        // can't do anything
        return null;
      }
      navigatable = service.getDefaultNavigatable();
    }
    return navigatable;
  }

  private void createSignature(
      Navigatable navigatable, ProgramSelection selection, String delimiter) {
    navigatable = getNavigatableProgram(navigatable);
    if (navigatable != null) {
      FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, delimiter);
      FizzPanel panel = new FizzPanel("Fizz - Obtained Signature", signature.getSignature());
    }
  }

  private void createRawSignature(Navigatable navigatable, ProgramSelection selection) {
    navigatable = getNavigatableProgram(navigatable);
    if (navigatable != null) {
      FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, "");
      FizzPanel panel = new FizzPanel("Fizz - Obtained Raw Signature", signature.getRaw());
    }
  }
}
