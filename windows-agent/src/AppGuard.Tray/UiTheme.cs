using System.Drawing;
using System.Windows.Forms;

namespace AppGuard.Tray;

internal static class UiTheme
{
    public static readonly Color WindowBack = Color.FromArgb(246, 248, 251);
    public static readonly Color CardBack = Color.White;
    public static readonly Color Border = Color.FromArgb(214, 220, 229);
    public static readonly Color Text = Color.FromArgb(28, 36, 48);
    public static readonly Color Muted = Color.FromArgb(96, 108, 126);
    public static readonly Color Accent = SystemColors.Highlight;
    public static readonly Color AccentText = SystemColors.HighlightText;
    public static readonly Color Danger = Color.FromArgb(196, 40, 32);

    public static void ApplyForm(Form form)
    {
        form.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular, GraphicsUnit.Point);
        form.BackColor = WindowBack;
    }

    public static void StyleHeadline(Label label)
    {
        label.Font = new Font("Segoe UI", 18f, FontStyle.Bold, GraphicsUnit.Point);
        label.ForeColor = Text;
    }

    public static void StyleBody(Label label, bool muted = false)
    {
        label.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular, GraphicsUnit.Point);
        label.ForeColor = muted ? Muted : Text;
    }

    public static void StylePrimaryButton(Button button)
    {
        StyleButtonBase(button);
        button.BackColor = Accent;
        button.ForeColor = AccentText;
        button.FlatAppearance.BorderColor = Accent;
    }

    public static void StyleSecondaryButton(Button button)
    {
        StyleButtonBase(button);
        button.BackColor = CardBack;
        button.ForeColor = Text;
        button.FlatAppearance.BorderColor = Border;
    }

    public static void StyleDangerButton(Button button)
    {
        StyleButtonBase(button);
        button.BackColor = Danger;
        button.ForeColor = Color.White;
        button.FlatAppearance.BorderColor = Danger;
    }

    public static void StyleButtonBase(Button button)
    {
        button.AutoSize = true;
        button.FlatStyle = FlatStyle.Flat;
        button.FlatAppearance.BorderSize = 1;
        button.Padding = new Padding(12, 5, 12, 5);
        button.MinimumSize = new Size(0, 34);
        button.Cursor = Cursors.Hand;
    }

    public static void StyleList(ListView list)
    {
        list.BackColor = CardBack;
        list.ForeColor = Text;
        list.BorderStyle = BorderStyle.FixedSingle;
        list.GridLines = false;
        list.HideSelection = false;
        list.Font = new Font("Segoe UI", 9.25f);
    }

    public static void StyleInput(TextBox textBox)
    {
        textBox.BackColor = Color.White;
        textBox.ForeColor = Text;
        textBox.BorderStyle = BorderStyle.FixedSingle;
        textBox.Font = new Font("Segoe UI", 9.5f);
    }

    public static Panel CreateHeader(string title, string subtitle)
    {
        var panel = new Panel { Dock = DockStyle.Top, Height = 86, BackColor = CardBack, Padding = new Padding(22, 16, 22, 10) };
        var titleLabel = new Label { AutoSize = true, Text = title, Location = new Point(22, 14) };
        StyleHeadline(titleLabel);
        titleLabel.Font = new Font("Segoe UI", 16f, FontStyle.Bold);
        var subLabel = new Label { AutoSize = true, MaximumSize = new Size(850, 0), Text = subtitle, Location = new Point(24, 50) };
        StyleBody(subLabel, muted: true);
        panel.Controls.Add(titleLabel);
        panel.Controls.Add(subLabel);
        return panel;
    }
}
