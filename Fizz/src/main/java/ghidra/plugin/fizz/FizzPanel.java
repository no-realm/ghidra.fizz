package ghidra.plugin.fizz;

import javax.swing.*;
import java.awt.*;

/**
 * @author quosego <https://github.com/quosego>
 * @version Mar 11, 2019
 */
class FizzPanel {

  FizzPanel(String title, String message) {
    create(title, message);
  }

  private void create(String title, String message) {
    JTextArea textArea = new JTextArea(3, 50);
    textArea.append(message);
    JPanel panel = new JPanel();
    panel.add(
        new JScrollPane(
            textArea,
            ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
            ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED),
        BorderLayout.SOUTH);
    int result = JOptionPane.showConfirmDialog(null, panel, title, JOptionPane.DEFAULT_OPTION, JOptionPane.PLAIN_MESSAGE);

    if (result == JOptionPane.OK_OPTION) {
      textArea.selectAll();
      textArea.copy();
    }
  }
}
