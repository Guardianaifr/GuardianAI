import React from 'react'

export class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error("GuardianAI Dashboard error boundary caught exception:", error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-6 font-sans">
          <div className="max-w-md w-full p-6 rounded-xl bg-slate-900 border border-red-900/60 shadow-xl space-y-4">
            <div className="flex items-center gap-3 text-red-400">
              <svg className="w-6 h-6 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <h2 className="text-lg font-semibold text-white">GuardianAI Dashboard Error</h2>
            </div>
            <p className="text-xs text-slate-400 leading-relaxed">
              {this.state.error?.message || "An unexpected error occurred while rendering the dashboard."}
            </p>
            <div className="pt-2">
              <button
                onClick={() => window.location.reload()}
                className="w-full py-2 px-4 rounded-lg bg-[#836EF9] hover:brightness-110 text-white text-xs font-semibold transition"
              >
                Reload Dashboard
              </button>
            </div>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary
