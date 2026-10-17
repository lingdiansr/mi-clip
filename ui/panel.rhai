fn view(ctx) {
    column([
        text("Mi Clip").with_style(style().font_size(px(16))),
        text("尚未连接").with_style(style().text_color(theme_color("text_muted"))),
        text("等待设备认证").with_style(style().text_color(theme_color("text_muted"))),
    ]).with_style(
        style().width(relative(1.0))
            .gap(px(10)).padding(px(20)).background(theme_color("surface"))
            .text_color(theme_color("text_primary"))
    )
}
