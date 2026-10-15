#include "aether/android/framework.hpp"

namespace aether::android {
std::span<const ApiSupport> api_registry() noexcept {
    // "tested" means the stated bounded behavior has executable regression coverage.
    // Unimplemented overloads are absent and fail with the full class/name/signature.
    static constexpr ApiSupport entries[]{
        {"Landroid/app/Activity;", "<init>", "()V", ApiStatus::partial,
         "One activity attached to its application context"},
        {"Landroid/app/Activity;", "onCreate", "(Landroid/os/Bundle;)V", ApiStatus::partial,
         "Null initial state; super-call required"},
        {"Landroid/app/Activity;", "onStart", "()V", ApiStatus::partial, "Basic lifecycle super-call"},
        {"Landroid/app/Activity;", "onResume", "()V", ApiStatus::partial, "Basic lifecycle super-call"},
        {"Landroid/app/Activity;", "onPause", "()V", ApiStatus::partial, "Basic lifecycle super-call"},
        {"Landroid/app/Activity;", "onStop", "()V", ApiStatus::partial, "Basic lifecycle super-call"},
        {"Landroid/app/Activity;", "onRestart", "()V", ApiStatus::partial, "Basic lifecycle super-call"},
        {"Landroid/app/Activity;", "onDestroy", "()V", ApiStatus::partial, "Basic lifecycle super-call"},
        {"Landroid/app/Activity;", "onWindowFocusChanged", "(Z)V", ApiStatus::partial,
         "Focus callback separate from resumed state"},
        {"Landroid/app/Activity;", "setContentView", "(Landroid/view/View;)V", ApiStatus::partial,
         "One retained content root"},
        {"Landroid/app/Activity;", "findViewById", "(I)Landroid/view/View;", ApiStatus::partial,
         "Depth-first search of the content tree"},
        {"Landroid/app/Activity;", "dispatchTouchEvent", "(Landroid/view/MotionEvent;)Z", ApiStatus::partial,
         "Single primary pointer; managed override then retained-tree hit testing"},
        {"Landroid/app/Activity;", "dispatchKeyEvent", "(Landroid/view/KeyEvent;)Z", ApiStatus::partial,
         "Managed override; Tab traversal and Enter/Space button activation"},
        {"Landroid/view/InputEvent;", "getSource", "()I", ApiStatus::partial,
         "Mouse, touchscreen or keyboard source during dispatch"},
        {"Landroid/view/MotionEvent;", "getX", "()F", ApiStatus::partial,
         "Single-pointer activity-local logical coordinate during dispatch"},
        {"Landroid/view/MotionEvent;", "getY", "()F", ApiStatus::partial,
         "Single-pointer activity-local logical coordinate during dispatch"},
        {"Landroid/view/MotionEvent;", "getAction", "()I", ApiStatus::partial,
         "DOWN/UP/MOVE/CANCEL; no secondary-pointer action bits"},
        {"Landroid/view/MotionEvent;", "getActionMasked", "()I", ApiStatus::partial,
         "DOWN/UP/MOVE/CANCEL; no secondary pointers"},
        {"Landroid/view/MotionEvent;", "getPointerCount", "()I", ApiStatus::partial, "One primary pointer"},
        {"Landroid/view/MotionEvent;", "getPointerId", "(I)I", ApiStatus::partial,
         "Stable guest ID zero; only index zero is valid"},
        {"Landroid/view/KeyEvent;", "getAction", "()I", ApiStatus::partial, "DOWN or UP during dispatch"},
        {"Landroid/view/KeyEvent;", "getKeyCode", "()I", ApiStatus::partial,
         "Android keycode; unsupported host keys map to KEYCODE_UNKNOWN"},
        {"Landroid/view/KeyEvent;", "getMetaState", "()I", ApiStatus::partial,
         "Aggregate Shift/Alt/Ctrl/Meta modifier bits"},
        {"Landroid/view/KeyEvent;", "getRepeatCount", "()I", ApiStatus::partial,
         "Consecutive down repeats for the same host key"},
        {"Landroid/content/Context;", "getPackageName", "()Ljava/lang/String;", ApiStatus::tested,
         "Manifest package name"},
        {"Landroid/content/Context;", "getApplicationContext", "()Landroid/content/Context;",
         ApiStatus::tested, "Per-session application context"},
        {"Landroid/content/Context;", "getResources", "()Landroid/content/res/Resources;", ApiStatus::tested,
         "Per-package compiled resources"},
        {"Landroid/content/Context;", "getPackageManager", "()Landroid/content/pm/PackageManager;",
         ApiStatus::tested, "Default-deny permission and feature reporting"},
        {"Landroid/content/Context;", "getString", "(I)Ljava/lang/String;", ApiStatus::partial,
         "Default scalar string resources and aliases"},
        {"Landroid/content/Context;", "getText", "(I)Ljava/lang/CharSequence;", ApiStatus::partial,
         "Default scalar string resources and aliases"},
        {"Landroid/content/Context;", "checkSelfPermission", "(Ljava/lang/String;)I", ApiStatus::partial,
         "PERMISSION_DENIED; no host capability is granted"},
        {"Landroid/content/Context;", "checkCallingOrSelfPermission", "(Ljava/lang/String;)I",
         ApiStatus::partial, "PERMISSION_DENIED; no host capability is granted"},
        {"Landroid/content/Context;", "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;",
         ApiStatus::partial, "Throws UnsupportedOperationException naming the service"},
        {"Landroid/content/res/Resources;", "getString", "(I)Ljava/lang/String;", ApiStatus::partial,
         "Default scalar string resources and aliases"},
        {"Landroid/content/res/Resources;", "getText", "(I)Ljava/lang/CharSequence;", ApiStatus::partial,
         "Default scalar string resources and aliases"},
        {"Landroid/content/res/Resources;", "getIdentifier",
         "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)I", ApiStatus::partial,
         "Package/type/name lookup; missing name returns zero"},
        {"Landroid/content/pm/PackageManager;", "checkPermission", "(Ljava/lang/String;Ljava/lang/String;)I",
         ApiStatus::partial, "PERMISSION_DENIED for every permission/package"},
        {"Landroid/content/pm/PackageManager;", "hasSystemFeature", "(Ljava/lang/String;)Z",
         ApiStatus::partial, "False: no optional Android feature advertised"},
        {"Landroid/widget/LinearLayout;", "<init>", "(Landroid/content/Context;)V", ApiStatus::partial,
         "Retained single-axis layout"},
        {"Landroid/widget/LinearLayout;", "setOrientation", "(I)V", ApiStatus::partial,
         "HORIZONTAL=0 or VERTICAL=1"},
        {"Landroid/view/ViewGroup;", "addView", "(Landroid/view/View;)V", ApiStatus::partial,
         "Single-parent acyclic tree; 256-node quota"},
        {"Landroid/widget/TextView;", "<init>", "(Landroid/content/Context;)V", ApiStatus::partial,
         "Retained plain text view"},
        {"Landroid/widget/Button;", "<init>", "(Landroid/content/Context;)V", ApiStatus::partial,
         "Retained text button"},
        {"Landroid/widget/TextView;", "setText", "(Ljava/lang/CharSequence;)V", ApiStatus::partial,
         "Copies String/StringBuilder text; null becomes empty"},
        {"Landroid/widget/TextView;", "setText", "(I)V", ApiStatus::partial,
         "Resolves package string resource"},
        {"Landroid/widget/TextView;", "getText", "()Ljava/lang/CharSequence;", ApiStatus::partial,
         "Returns current plain text snapshot"},
        {"Landroid/view/View;", "setOnClickListener", "(Landroid/view/View$OnClickListener;)V",
         ApiStatus::partial, "Retains listener; null removes it"},
        {"Landroid/view/View;", "performClick", "()Z", ApiStatus::partial,
         "Calls actual managed listener; no sound or accessibility service"},
        {"Landroid/view/View;", "setEnabled", "(Z)V", ApiStatus::partial, "Controls host input eligibility"},
        {"Landroid/view/View;", "isEnabled", "()Z", ApiStatus::tested, "Returns retained enabled state"},
        {"Landroid/view/View;", "setId", "(I)V", ApiStatus::partial,
         "App-defined nonnegative view ID or NO_ID"},
        {"Landroid/view/View;", "getId", "()I", ApiStatus::tested, "Returns retained view ID"},
        {"Landroid/view/View$OnClickListener;", "onClick", "(Landroid/view/View;)V", ApiStatus::partial,
         "Interface dispatch to the app's managed implementation"},
        {"Landroid/app/Activity;", "requestPermissions", "([Ljava/lang/String;I)V", ApiStatus::not_started,
         "No permission approval UI; rejects as unsupported"},
        {"Landroid/webkit/WebView;", "<init>", "(Landroid/content/Context;)V", ApiStatus::not_started,
         "No WebView implementation"},
        {"Landroid/view/LayoutInflater;", "inflate", "(ILandroid/view/ViewGroup;)Landroid/view/View;",
         ApiStatus::not_started, "No XML layout inflation"},
        {"Landroid/content/Context;", "startActivity", "(Landroid/content/Intent;)V", ApiStatus::not_started,
         "No intent/activity stack implementation"}};
    return entries;
}
std::string_view status_name(ApiStatus status) noexcept {
    switch (status) {
    case ApiStatus::not_started:
        return "not-started";
    case ApiStatus::stub:
        return "stub";
    case ApiStatus::partial:
        return "partial";
    case ApiStatus::tested:
        return "tested";
    }
    return "not-started";
}
std::string_view lifecycle_name(Lifecycle state) noexcept {
    switch (state) {
    case Lifecycle::empty:
        return "empty";
    case Lifecycle::created:
        return "created";
    case Lifecycle::started:
        return "started";
    case Lifecycle::resumed:
        return "resumed";
    case Lifecycle::paused:
        return "paused";
    case Lifecycle::stopped:
        return "stopped";
    case Lifecycle::destroyed:
        return "destroyed";
    case Lifecycle::failed:
        return "failed";
    }
    return "failed";
}
} // namespace aether::android
