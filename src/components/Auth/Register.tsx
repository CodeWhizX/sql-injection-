import React, { useState } from 'react';
import { Shield, Mail, Lock, User, ArrowRight, AlertCircle, Loader2, CheckCircle2 } from 'lucide-react';
import { Link, useNavigate } from 'react-router-dom';
import { useUserAuth } from '../../contexts/UserAuthContext';
import { auth, signInWithPopup, googleProvider } from '../../firebase';
import toast from 'react-hot-toast';

export const Register: React.FC = () => {
  const navigate = useNavigate();
  const { registerLocal } = useUserAuth();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!name || !email || !password || !confirmPassword) {
      toast.error("All fields are required");
      return;
    }

    if (password !== confirmPassword) {
      toast.error("Access keys do not match");
      return;
    }

    if (password.length < 6) {
      toast.error("Access key must be at least 6 characters");
      return;
    }

    setLoading(true);

    try {
      await registerLocal(name, email, password);
      toast.success("New Operator enlisted successfully");
      setTimeout(() => {
        navigate('/login');
      }, 1500);
    } catch (err: any) {
      console.error("Registration error:", err);
      toast.error(err.message || "Failed to enlist new operator");
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleLogin = async () => {
    setLoading(true);
    try {
      await signInWithPopup(auth, googleProvider);
      toast.success("SSO Registration successful");
    } catch (err: any) {
      console.error("Google login error:", err);
      toast.error(err.message || "Failed to register with Google.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-4 font-sans">
      <div className="w-full max-w-md">
        {/* Logo/Brand */}
        <div className="text-center mb-8">
          <div className="inline-flex p-3 bg-emerald-500/10 rounded-2xl mb-4 border border-emerald-500/20">
            <Shield className="w-10 h-10 text-emerald-500" />
          </div>
          <h1 className="text-3xl font-black text-zinc-100 tracking-tight">
            Edu<span className="text-emerald-500">Scanner</span>
          </h1>
          <p className="text-zinc-500 text-sm mt-2">Advanced SQL Injection Security Platform</p>
        </div>

        {/* Register Card */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-2xl overflow-hidden shadow-2xl shadow-emerald-500/5">
          <div className="p-8">
            <h2 className="text-xl font-bold text-zinc-100 mb-6">Enlist New Operator</h2>
            
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-1.5">
                <label className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider ml-1">Full Name</label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                  <input
                    type="text"
                    required
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all"
                    placeholder="John Doe"
                  />
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider ml-1">Email Address</label>
                <div className="relative">
                  <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                  <input
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all"
                    placeholder="operator@eduscanner.io"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider ml-1">Access Key</label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                    <input
                      type="password"
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all"
                      placeholder="••••••••"
                    />
                  </div>
                </div>
                <div className="space-y-1.5">
                  <label className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider ml-1">Confirm Key</label>
                  <div className="relative">
                    <CheckCircle2 className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
                    <input
                      type="password"
                      required
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="w-full bg-zinc-950 border border-zinc-800 rounded-xl py-3 pl-10 pr-4 text-zinc-200 text-sm focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all"
                      placeholder="••••••••"
                    />
                  </div>
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-emerald-500 hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed text-zinc-950 font-bold py-3 rounded-xl transition-all flex items-center justify-center space-x-2 mt-2"
              >
                {loading ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <>
                    <span>Register</span>
                    <ArrowRight className="w-4 h-4" />
                  </>
                )}
              </button>
            </form>

            <div className="relative my-8">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-zinc-800"></div>
              </div>
              <div className="relative flex justify-center text-[10px] uppercase font-bold">
                <span className="bg-zinc-900 px-4 text-zinc-600 tracking-widest">Or join with</span>
              </div>
            </div>

            <button
              onClick={handleGoogleLogin}
              disabled={loading}
              className="w-full bg-zinc-950 border border-zinc-800 hover:border-zinc-700 disabled:opacity-50 disabled:cursor-not-allowed text-zinc-300 font-bold py-3 rounded-xl transition-all flex items-center justify-center space-x-3"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24">
                <path
                  fill="currentColor"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="currentColor"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="currentColor"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="currentColor"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 12-4.53z"
                />
              </svg>
              <span>Google SSO</span>
            </button>
          </div>
          
          <div className="bg-zinc-950/50 p-6 border-t border-zinc-800 text-center">
            <p className="text-zinc-500 text-xs">
              Already have an account?{' '}
              <Link
                to="/login"
                className="text-emerald-500 hover:text-emerald-400 font-bold transition-colors"
              >
                Login
              </Link>
            </p>
          </div>
        </div>
        
        <p className="text-center text-zinc-600 text-[10px] mt-8 uppercase tracking-[0.2em] font-bold">
          Authorized Personnel Only • EduScanner v2.4.0
        </p>
      </div>
    </div>
  );
};
