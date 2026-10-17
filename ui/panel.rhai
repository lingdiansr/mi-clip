fn view(ctx) {
    let detail = "等待设备认证";
    let children = [
        row([
            text("Mi Clip").with_style(style().font_size(px(13)).font_weight(600)),
            text("尚未连接").with_style(
                style().font_size(px(12)).text_color(theme_color("status_color"))
            ),
        ]).with_style(style().items_center().gap(px(6))),
    ];
    if detail != "" {
        children.push(text(detail).with_style(
            style().font_size(px(12)).text_color(theme_color("text_muted"))
        ));
    }
    column(children).with_style(
        style().width(relative(1.0))
            .font_size(px(12)).gap(px(4)).padding(px(14)).background(theme_color("surface"))
            .text_color(theme_color("text_primary"))
    )
}
