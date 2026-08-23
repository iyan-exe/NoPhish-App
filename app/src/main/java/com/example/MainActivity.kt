package com.example

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.CubicBezierEasing
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VerifiedUser
import androidx.compose.material.icons.outlined.History
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material.icons.outlined.VerifiedUser
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.MainViewModel
import com.example.ui.screens.HistoryScreen
import com.example.ui.screens.ScanScreen
import com.example.ui.screens.ThreatIntelScreen
import com.example.ui.theme.MyApplicationTheme
import com.example.ui.theme.NothingBlack
import com.example.ui.theme.NothingBorder
import com.example.ui.theme.NothingGrey
import com.example.ui.theme.NothingRed
import com.example.ui.theme.NothingSurface
import com.example.ui.theme.NothingWhite

enum class AppTab(
    val title: String,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
) {
    SCAN("SCANNER", Icons.Filled.Security, Icons.Outlined.Security, "tab_scanner"),
    HISTORY("AUDIT", Icons.Filled.History, Icons.Outlined.History, "tab_history"),
    WHITELIST("INTEL", Icons.Filled.VerifiedUser, Icons.Outlined.VerifiedUser, "tab_whitelist")
}

class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                MainAppContent(viewModel = viewModel)
            }
        }
    }
}

@Composable
fun MainAppContent(viewModel: MainViewModel) {
    var selectedTab by rememberSaveable { mutableStateOf(AppTab.SCAN) }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = NothingBlack,
        bottomBar = {
            NothingBottomNavBar(
                selectedTab = selectedTab,
                onTabSelected = { selectedTab = it }
            )
        }
    ) { innerPadding ->
        // 120Hz Ultra-smooth directional slide & fade transition
        AnimatedContent(
            targetState = selectedTab,
            transitionSpec = {
                val isForward = targetState.ordinal > initialState.ordinal
                val slideOffset = if (isForward) 220 else -220
                val exitOffset = if (isForward) -220 else 220

                (slideInHorizontally(
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioLowBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    ),
                    initialOffsetX = { slideOffset }
                ) + fadeIn(
                    animationSpec = tween(220, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f))
                )).togetherWith(
                    slideOutHorizontally(
                        animationSpec = spring(
                            dampingRatio = Spring.DampingRatioNoBouncy,
                            stiffness = Spring.StiffnessMedium
                        ),
                        targetOffsetX = { exitOffset }
                    ) + fadeOut(
                        animationSpec = tween(160, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f))
                    )
                )
            },
            modifier = Modifier.fillMaxSize(),
            label = "tab_120hz_transition"
        ) { targetTab ->
            when (targetTab) {
                AppTab.SCAN -> ScanScreen(
                    viewModel = viewModel,
                    modifier = Modifier.padding(innerPadding)
                )
                AppTab.HISTORY -> HistoryScreen(
                    viewModel = viewModel,
                    onNavigateToScan = { selectedTab = AppTab.SCAN },
                    modifier = Modifier.padding(innerPadding)
                )
                AppTab.WHITELIST -> ThreatIntelScreen(
                    viewModel = viewModel,
                    onNavigateToScan = { selectedTab = AppTab.SCAN },
                    modifier = Modifier.padding(innerPadding)
                )
            }
        }
    }
}

/**
 * Nothing OS Minimalist Navigation Bar with 120Hz Spring-Physics Pill Indicators
 */
@Composable
fun NothingBottomNavBar(
    selectedTab: AppTab,
    onTabSelected: (AppTab) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .background(NothingBlack)
            .border(
                width = 1.dp,
                color = NothingBorder,
                shape = androidx.compose.ui.graphics.RectangleShape
            )
            .navigationBarsPadding()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceAround,
            verticalAlignment = Alignment.CenterVertically
        ) {
            AppTab.entries.forEach { tab ->
                val isSelected = selectedTab == tab

                // 120Hz Dynamic Scale & Color Transitions
                val tabScale by animateFloatAsState(
                    targetValue = if (isSelected) 1f else 0.94f,
                    animationSpec = spring(
                        dampingRatio = Spring.DampingRatioMediumBouncy,
                        stiffness = Spring.StiffnessMediumLow
                    ),
                    label = "tab_scale"
                )

                val backgroundColor by animateColorAsState(
                    targetValue = if (isSelected) NothingWhite else Color(0xFF111111),
                    animationSpec = tween(200, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f)),
                    label = "tab_bg"
                )

                val contentColor by animateColorAsState(
                    targetValue = if (isSelected) NothingBlack else NothingGrey,
                    animationSpec = tween(200, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f)),
                    label = "tab_content_color"
                )

                val borderColor by animateColorAsState(
                    targetValue = if (isSelected) NothingWhite else Color(0xFF222222),
                    animationSpec = tween(200, easing = CubicBezierEasing(0.2f, 0f, 0f, 1f)),
                    label = "tab_border"
                )

                val interactionSource = remember { MutableInteractionSource() }

                Box(
                    modifier = Modifier
                        .scale(tabScale)
                        .clip(CircleShape)
                        .background(backgroundColor)
                        .border(1.dp, borderColor, CircleShape)
                        .clickable(
                            interactionSource = interactionSource,
                            indication = null
                        ) { onTabSelected(tab) }
                        .padding(horizontal = 16.dp, vertical = 9.dp)
                        .testTag(tab.testTag),
                    contentAlignment = Alignment.Center
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.Center
                    ) {
                        if (isSelected) {
                            Box(
                                modifier = Modifier
                                    .size(5.dp)
                                    .clip(CircleShape)
                                    .background(NothingRed)
                            )
                            Spacer(modifier = Modifier.width(6.dp))
                        }

                        Icon(
                            imageVector = if (isSelected) tab.selectedIcon else tab.unselectedIcon,
                            contentDescription = tab.title,
                            tint = contentColor,
                            modifier = Modifier.size(17.dp)
                        )

                        Spacer(modifier = Modifier.width(6.dp))

                        Text(
                            text = tab.title,
                            fontFamily = FontFamily.Monospace,
                            fontSize = 11.sp,
                            fontWeight = if (isSelected) FontWeight.Bold else FontWeight.Medium,
                            letterSpacing = 1.sp,
                            color = contentColor
                        )
                    }
                }
            }
        }
    }
}

