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
  private int programSubMenuPosition = 0;

  private static final String CONTEXT_GROUP = "Fizz";
  private static final String MENU_CONTEXT = "Fizz Signature";

  //
  private static final String CONTEXT_GHIDRA_OPTION_SELECTION =
      "Obtain a Ghidra Signature from Selection";
  private static final String[] SET_CONTEXT_GHIDRA_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_GHIDRA_OPTION_SELECTION
  };
  private static final String[] SET_CONTEXT_GHIDRA_SELECTION = {
    ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_GHIDRA_OPTION_SELECTION
  };

  //
  private static final String CONTEXT_COMMON_OPTION_SELECTION =
      "Obtain a Common Signature from Selection";
  private static final String[] SET_CONTEXT_COMMON_POPUPPATH = {
    MENU_CONTEXT, CONTEXT_COMMON_OPTION_SELECTION
  };
  private static final String[] SET_CONTEXT_COMMON_SELECTION = {
    ToolConstants.MENU_SELECTION, MENU_CONTEXT, CONTEXT_COMMON_OPTION_SELECTION
  };

  //
  private static final String CONTEXT_RAW_OPTION_SELECTION =
      "Obtain a RAW Signature from Selection";
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
    System.out.println(selection);
    System.out.println(popup);
    System.out.println(action);
    System.out.println("------------");
    MenuData menuData = new MenuData(selection, CONTEXT_GROUP);
    menuData.setMenuSubGroup(Integer.toString(programSubMenuPosition));
    action.setMenuBarData(menuData);
    action.setPopupMenuData(new MenuData(popup, CONTEXT_GROUP));
    tool.addAction(action);
    programSubMenuPosition++;
  }

  // =============================================================================================
  // Action Provider methods
  // =============================================================================================

  private void createActions() {
    createRawSignatureContext();
    createGhidraSignatureContext();
    createCommonSignatureContext();
    tool.setMenuGroup(new String[] {MENU_CONTEXT}, CONTEXT_GROUP);
  }

  private void createRawSignatureContext() {
    DockingAction action =
        new NavigatableContextAction(CONTEXT_RAW_OPTION_SELECTION, this.tool.getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createRawSignature(context.getNavigatable(), copySelection(context.getSelection()));
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };
    // set hotkey: 1 + ALT
    action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_1, InputEvent.ALT_DOWN_MASK));

    // add to context menu
    createDockingAction(action, SET_CONTEXT_RAW_SELECTION, SET_CONTEXT_RAW_POPUPPATH);
  }

  private void createGhidraSignatureContext() {
    DockingAction action =
        new NavigatableContextAction(CONTEXT_GHIDRA_OPTION_SELECTION, this.tool.getName()) {
          @Override
          protected void actionPerformed(NavigatableActionContext context) {
            createSignature(context.getNavigatable(), copySelection(context.getSelection()), "..");
          }

          @Override
          protected boolean isEnabledForContext(NavigatableActionContext context) {
            return context.hasSelection() && context.getNavigatable().isVisible();
          }
        };

    // set hotkey: 2 + ALT
    action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_2, InputEvent.ALT_DOWN_MASK));

    // add to context menu
    createDockingAction(action, SET_CONTEXT_GHIDRA_SELECTION, SET_CONTEXT_GHIDRA_POPUPPATH);
  }

  private void createCommonSignatureContext() {
    DockingAction action =
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
    // set hotkey: 3 + ALT
    action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_3, InputEvent.ALT_DOWN_MASK));

    // add to context menu
    createDockingAction(action, SET_CONTEXT_COMMON_SELECTION, SET_CONTEXT_COMMON_POPUPPATH);
  }

  // =============================================================================================
  // Action Listener helpers
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

  // =============================================================================================
  // Action Listener methods
  // =============================================================================================

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
      FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, "xx");
      FizzPanel panel = new FizzPanel("Fizz - Obtained Raw Signature", signature.getRaw());
    }
  }
}
