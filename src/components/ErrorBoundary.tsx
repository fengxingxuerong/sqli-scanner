// ErrorBoundary.tsx — 全局 React 错误边界
// 组件渲染异常时显示降级 UI，防白屏。用户可点「刷新页面」恢复。

import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Box, Typography, Button, Alert } from '@mui/material';
import RefreshIcon from '@mui/icons-material/Refresh';
import i18n from '../i18n';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[ErrorBoundary]', error, errorInfo);
  }

  handleReload = () => {
    this.setState({ hasError: false, error: null });
    window.location.reload();
  };

  render() {
    if (this.state.hasError) {
      return (
        <Box
          sx={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            gap: 2,
            p: 3,
          }}
        >
          <Alert severity="error" variant="outlined" sx={{ maxWidth: 600 }}>
            <Typography variant="body2" sx={{ whiteSpace: 'pre-wrap' }}>
              {this.state.error?.message || i18n.t('common.pageErrorTitle')}
            </Typography>
          </Alert>
          <Button
            variant="contained"
            startIcon={<RefreshIcon />}
            onClick={this.handleReload}
          >
            {i18n.t('common.refreshPage')}
          </Button>
        </Box>
      );
    }
    return this.props.children;
  }
}

export default ErrorBoundary;