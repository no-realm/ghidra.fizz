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
 * @version Mar 15, 2019
 */
class FizzContext {
  private PluginTool tool;

  private int programSubMenuPosition = 0;

  private static final String CONTEXT_GROUP = "Fizz";
  private static final String MENU_CONTEXT = "Fizz Signature";

  FizzContext(PluginTool tool) {
    this.tool = tool;
    createActions();
  }

  // =============================================================================================
  // Docking Action helper
  // =============================================================================================

  private void addDockingAction(DockingAction action, String[] selection, String[] popup) {
    MenuData menuData = new MenuData(selection, CONTEXT_GROUP);
    menuData.setMenuSubGroup(Integer.toString(programSubMenuPosition));
    action.setMenuBarData(menuData);
    action.setPopupMenuData(new MenuData(popup, CONTEXT_GROUP));
    tool.addAction(action);
    programSubMenuPosition++;
  }

  private String[] createContextPopup(String optionSelection) {
    return new String[] {MENU_CONTEXT, optionSelection};
  }

  private String[] createContextSelection(String optionSelection) {
    return new String[] {ToolConstants.MENU_SELECTION, MENU_CONTEXT, optionSelection};
  }

  // =============================================================================================
  // Action Provider methods
  // =============================================================================================

  private void createActions() {
    createSelectedAreaSignatureContext();
    createSelectedBlockSignatureContext();
    createSelectedFunctionSignatureContext();
    tool.setMenuGroup(new String[] {MENU_CONTEXT}, CONTEXT_GROUP);
  }

  private void createSelectedAreaSignatureContext() {
    String option = "Create a Signature for the Area";
    // new docker
    DockingAction action = null;
    try {
      // create docking action
      action =
          new NavigatableContextAction(option, this.tool.getName()) {
            @Override
            protected void actionPerformed(NavigatableActionContext context) {
              createSelectionSignature(
                  context.getNavigatable(), copySelection(context.getSelection()));
            }

            @Override
            protected boolean isEnabledForContext(NavigatableActionContext context) {
              return context.hasSelection() && context.getNavigatable().isVisible();
            }
          };

      // set hotkey: A + CTRL
      action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_A, InputEvent.CTRL_DOWN_MASK));
          
      // add to context menu
      addDockingAction(action, createContextSelection(option), createContextPopup(option));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void createSelectedBlockSignatureContext() {
    String option = "Create a Signature for the Block";
    // new docker
    DockingAction action = null;
    try {
      // create docking action
      action =
          new NavigatableContextAction(option, this.tool.getName()) {
            @Override
            protected void actionPerformed(NavigatableActionContext context) {
              createBlockSignature(context.getNavigatable(), copySelection(context.getSelection()));
            }

            @Override
            protected boolean isEnabledForContext(NavigatableActionContext context) {
              return context.hasSelection() && context.getNavigatable().isVisible();
            }
          };

      // set hotkey: B + CTRL
      action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_B, InputEvent.CTRL_DOWN_MASK));

      // add to context menu
      addDockingAction(action, createContextSelection(option), createContextPopup(option));
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void createSelectedFunctionSignatureContext() {
    String option = "Create a Signature for the Function";
    // new docker
    DockingAction action = null;
    try {
      // create docking action
      action =
          new NavigatableContextAction(option, this.tool.getName()) {
            @Override
            protected void actionPerformed(NavigatableActionContext context) {
              createFunctionSignature(
                  context.getNavigatable(), copySelection(context.getSelection()));
            }

            @Override
            protected boolean isEnabledForContext(NavigatableActionContext context) {
              return context.hasSelection() && context.getNavigatable().isVisible();
            }
          };

      // set hotkey: F + CTRL
      action.setKeyBindingData(new KeyBindingData(KeyEvent.VK_F, InputEvent.CTRL_DOWN_MASK));

      // add to context menu
      addDockingAction(action, createContextSelection(option), createContextPopup(option));
    } catch (Exception e) {
      e.printStackTrace();
    }
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

  private void createSelectionSignature(Navigatable navigatable, ProgramSelection selection) {
    navigatable = getNavigatableProgram(navigatable);
    if (navigatable != null) {
      FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, "..");
      FizzPanel panel =
          new FizzPanel(
              "Fizz - Obtained Selected Area Signature", 
              signature.getSelectedSignature());
    }
  }

  private void createBlockSignature(Navigatable navigatable, ProgramSelection selection) {
    navigatable = getNavigatableProgram(navigatable);
    if (navigatable != null) {
      FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, "..");
      // TODO
      FizzPanel panel =
          new FizzPanel(
              "Fizz - Obtained Selected Block Signature", 
              signature.getSelectedBlockSignature());
      // FizzPanel panel = new FizzPanel("Fizz - WIP", "this feature is being developed");
    }
  }

  private void createFunctionSignature(Navigatable navigatable, ProgramSelection selection) {
    navigatable = getNavigatableProgram(navigatable);
    if (navigatable != null) {
      FizzSignature signature = new FizzSignature(navigatable.getProgram(), selection, "..");
      // TODO
      FizzPanel panel =
          new FizzPanel(
              "Fizz - Obtained Selected Function Signature",
              signature.getSelectedFunctionSignature());
      // FizzPanel panel = new FizzPanel("Fizz - WIP", "this feature is being developed");
    }
  }
}
